from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import click
import time
from flask_principal import current_app, Principal, Permission, RoleNeed, Identity, identity_changed, \
    AnonymousIdentity, identity_loaded

app = Flask(__name__)

app.config['SECRET_KEY'] = '20190847'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True  # 关闭对模型修改的监控
db = SQLAlchemy(app)

secret_key = "zwf.20010928-3"  # 用于权限认证的安全密钥

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请您先登录后再进行相关操作!'

principals = Principal(app)
admin_permission = Permission(RoleNeed("ADMIN"))  # 管理员权限

# 用于描述user和role的多对多关系
# 角色<-->用户关联表
users_roles = db.Table('users_roles',
                       db.Column('user_id', db.INTEGER, db.ForeignKey('user.id')),
                       db.Column('role_id', db.INTEGER, db.ForeignKey('role.id')))


# 用户类ORM
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.INTEGER, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(20))  # 用户名字段
    password_hash = db.Column(db.String(128))  # 密码散列值
    secret_key = db.Column(db.String(128), default='')  # 管理员权限密码,用于验证该用户的角色，如果是普通用户，则该属性为空
    # 多对多关系
    roles = db.relationship('Role', secondary='users_roles', backref=db.backref('users', lazy='dynamic'))

    def __init__(self, name, username, password, key):  # 构造方法
        self.name = name
        self.username = username
        self.password = password
        self.secret_key = key

    def set_password(self, password):  # 接受密码作为参数，生成散列值
        self.password_hash = generate_password_hash(password)
        return self.password_hash

    def validate_password(self, password):  # 验证密码散列值是否正确，返回Bull值
        return check_password_hash(self.password_hash, password)

    def __repr__(self):  # 自定义输出对象
        return "<user_username:{0}>".format(self.username)


# 角色类ORM
class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)  # 角色名

    def __repr__(self):  # 自定义输出对象
        return "<Role_name:{0}>".format(self.name)


# 球员类ORM
class Players(db.Model):
    id = db.Column(db.INTEGER, primary_key=True)
    playername = db.Column(db.String(30))
    position = db.Column(db.String(30))
    number = db.Column(db.INTEGER)
    age = db.Column(db.INTEGER)
    height = db.Column(db.INTEGER)
    weight = db.Column(db.INTEGER)
    foot = db.Column(db.String(30))  # 惯用脚
    endurance = db.Column(db.INTEGER)  # 耐力
    speed = db.Column(db.INTEGER)  # 速度
    rush_with_ball = db.Column(db.INTEGER)  # 盘带
    pass_ball = db.Column(db.INTEGER)  # 传球
    shoot = db.Column(db.INTEGER)  # 射门
    defence = db.Column(db.INTEGER)  # 防守

    def __init__(self, playername, position, number, age, height, weight, foot, endurance, speed, rush_with_ball, shoot,
                 defence, pass_ball):
        self.playername = playername
        self.number = number
        self.position = position
        self.age = age
        self.height = height
        self.weight = weight
        self.foot = foot
        self.endurance = endurance
        self.speed = speed
        self.shoot = shoot
        self.rush_with_ball = rush_with_ball
        self.defence = defence
        self.pass_ball = pass_ball


@app.cli.command()  # 注册为命令
@click.option('--drop', is_flag=True, help='Create after drop.')
# 设置选项
def initdb(drop):
    """Initialize the database."""
    if drop:  # 判断是否输入了选项
        db.drop_all()
        click.echo('数据库删除成功')
    db.create_all()
    click.echo('数据库初始化成功')  # 输出提示信息


@app.cli.command()
@click.option('--username', prompt=True, help='The username usedto login.')
@click.option('--password', prompt=True, confirmation_prompt=True, help='The password used to login.')
@click.option('--obvious_name', prompt=True, help='Obvious name of the user.')
def admin(username, password, obvious_name):
    """Create user."""
    db.create_all()
    user = User.query.first()
    if user is not None:
        click.echo('正在更新用户信息')
        user.username = username
        user.set_password(password)  # 设置密码
        user.name = obvious_name
    else:
        click.echo('正在创建用户信息')
        user = User(username, obvious_name, password, secret_key)
        user.set_password(password)  # 设置密码
        db.session.add(user)
    db.session.commit()  # 提交数据库会话
    click.echo('用户信息创建（/更新）完成')


@login_manager.user_loader
def load_user(user_id):  # 创建用户加载回调函数，接受用户 ID 作为参数
    user = User.query.get(int(user_id))  # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象


@login_required
def admin_required(user_id):
    user = User.query.get(int(user_id))
    return user


@app.route('/', methods=['GET', 'POST'])
@login_required  # 用于视图保护
def index():
    players = Players.query.all()
    return render_template('index.html', players=players)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            for user in User.query.all():
                if user.username == username:
                    if user.validate_password(password):
                        login_user(user)
                        # identity_changed.send将当前应用的app对象和identity用户对象以信号形式发送出去
                        identity_changed.send(app, identity=Identity(user.id))
                        flash('登陆成功')
                        time.sleep(0.5)
                        return redirect(url_for('index'))
                    else:
                        flash('账号或密码输入错误')
                        return redirect(url_for('login'))
        except:
            register_name = request.form['new_name']
            register_username = request.form['regname']
            register_password = request.form['regpass']
            re_register_password = request.form['reregpass']
            secret_key = request.form['secret_key']

            if User.query.filter_by(username=register_username).first():
                flash("用户名已存在，请重新输入")
                return redirect(url_for('login'))
            if register_password == re_register_password:
                new_user = User(register_name, register_username, register_password, secret_key)
                new_user.set_password(register_password)
                db.session.add(new_user)
                db.session.commit()
                flash('您已经注册成功,将跳转回登录页面')
                return redirect(url_for('login'))
            else:
                flash("输入密码不一致或管理员密钥错误，请重新输入!!!")
    return render_template('login.html')


# 使用identity_loaded.connect_via(app)来接受信号，并载入权限
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user  # 初始化identity.user对象
    if hasattr(current_user, 'secret_key'):
        # 判断当前的current_user对象有无secret_key属性，因为当我logout（）的时候，
        # 会发送一个身份转变信号，将identity转换成AnonymousIdentity的状态，这时没有secret_key属性
        if current_user.secret_key == 'zwf.20010928-3':  # 判断安全密钥是否符合
            for role in Role.query.all():
                identity.provides.add(RoleNeed(role.name))  # 如果符合的话，将所有角色权限都添加到当前user的Permission中。

    return sender


@app.route('/logout')
@login_required  # 用于视图保护
def logout():
    logout_user()
    identity_changed.send(current_app, identity=AnonymousIdentity())
    flash('注销成功，再见！欢迎再次使用！')
    return redirect(url_for('login'))


@app.route('/visual_administer', methods=['GET', 'POST'])
@login_required  # 用于视图保护
def visual_administer():
    RW_count = Players.query.filter_by(position='右边锋（RW）').count()
    ST_count = Players.query.filter_by(position='中锋(ST)').count()
    LW_count = Players.query.filter_by(position='左边锋（LW）').count()
    SS_count = Players.query.filter_by(position='影子前锋（SS）').count()
    CAM_count = Players.query.filter_by(position='前腰（CAM）').count()
    CDM_count = Players.query.filter_by(position='后腰（CDM）').count()
    CB_count = Players.query.filter_by(position='中后卫(CB)').count()
    LB_count = Players.query.filter_by(position='左边后卫（LB）').count()
    RB_count = Players.query.filter_by(position='右边后卫（RB）').count()
    GK_count = Players.query.filter_by(position='门将(GK)').count()
    players = Players.query.all()
    if request.method == 'POST':
        position = request.form.get('select_position')
        if position == '右边锋（RW）':
            return redirect(url_for('show_rw'))
        if position == '中锋(ST)':
            return redirect(url_for('show_st'))
        if position == '左边锋（LW）':
            return redirect(url_for('show_lw'))
        if position == '影子前锋（SS）':
            return redirect(url_for('show_ss'))
        if position == '前腰（CAM）':
            return redirect(url_for('show_cam'))
        if position == '后腰（CDM）':
            return redirect(url_for('show_cdm'))
        if position == '中后卫(CB)':
            return redirect(url_for('show_cb'))
        if position == '左边后卫（LB）':
            return redirect(url_for('show_lb'))
        if position == '右边后卫（RB）':
            return redirect(url_for('show_rb'))
        if position == '门将(GK)':
            return redirect(url_for('show_gk'))
    return render_template('visual_administrator.html', players=players, rw=RW_count, st=ST_count, ss=SS_count,
                           lw=LW_count,
                           lb=LB_count, cam=CAM_count, cdm=CDM_count, cb=CB_count, rb=RB_count, gk=GK_count)


# 下面的路由用于可视化管理中的筛选
@app.route('/visual_administer/rw')
@login_required  # 用于视图保护
def show_rw():
    RW_players = [i for i in Players.query.filter_by(position='右边锋（RW）')]
    return render_template('show_position.html', players=RW_players, position='右边锋')


@app.route('/visual_administer/st')
@login_required  # 用于视图保护
def show_st():
    ST_players = [i for i in Players.query.filter_by(position='中锋(ST)')]
    return render_template('show_position.html', players=ST_players, position='中锋(ST)')


@app.route('/visual_administer/lw')
@login_required  # 用于视图保护
def show_lw():
    LW_players = [i for i in Players.query.filter_by(position='左边锋（LW）')]
    return render_template('show_position.html', players=LW_players, position='左边锋（LW）')


@app.route('/visual_administer/cam')
@login_required  # 用于视图保护
def show_cam():
    CAM_players = [i for i in Players.query.filter_by(position='前腰（CAM）')]
    return render_template('show_position.html', players=CAM_players, position='前腰（CAM）')


@app.route('/visual_administer/ss')
@login_required  # 用于视图保护
def show_ss():
    SS_players = [i for i in Players.query.filter_by(position='影子前锋（SS）')]
    return render_template('show_position.html', players=SS_players, position='影子前锋（SS）')


@app.route('/visual_administer/cdm')
@login_required  # 用于视图保护
def show_cdm():
    CDM_players = [i for i in Players.query.filter_by(position='后腰（CDM）')]
    return render_template('show_position.html', players=CDM_players, position='后腰（CDM）')


@app.route('/visual_administer/cb')
@login_required  # 用于视图保护
def show_cb():
    CB_players = [i for i in Players.query.filter_by(position='中后卫(CB)')]
    return render_template('show_position.html', players=CB_players, position='中后卫（CB）')


@app.route('/visual_administer/lb')
@login_required  # 用于视图保护
def show_lb():
    LB_players = [i for i in Players.query.filter_by(position='左边后卫（LB）')]
    return render_template('show_position.html', players=LB_players, position='左边后卫（LB）')


@app.route('/visual_administer/rb')
@login_required  # 用于视图保护
def show_rb():
    RB_players = [i for i in Players.query.filter_by(position='右边后卫（RB）')]
    return render_template('show_position.html', players=RB_players, position='右边后卫（RB）')


@app.route('/visual_administer/gk')
@login_required  # 用于视图保护
def show_gk():
    GK_players = [i for i in Players.query.filter_by(position='门将(GK)')]
    return render_template('show_position.html', players=GK_players, position='门将(GK)')


@app.route('/player/edit/<int:player_id>', methods=['GET', 'POST'])
@login_required  # 用于视图保护
@admin_permission.require(http_exception=403)  # 管理员权限保护
def edit(player_id):
    player = Players.query.get_or_404(player_id)
    a = player.number
    if request.method == 'POST':
        # 获取表单POST数据
        edited_name = request.form['edited_name']
        edited_positon = request.form['edited_position']
        edited_number = request.form['edited_number']
        edited_height = request.form.get('edited_height')
        edited_weight = request.form.get('edited_weight')
        edited_endurance = request.form.get('edited_endurance')
        edited_speed = request.form.get('edited_speed')
        edited_rush_with_ball = request.form.get('edited_rush_with_ball')
        edited_pass_ball = request.form.get('edited_pass_ball')
        edited_shoot = request.form.get('edited_shoot')
        edited_defence = request.form.get('edited_defence')
        edited_age = request.form.get('edited_age')
        edited_foot = request.form.get('edited_foot')
        # 数据库操作
        player.playername = edited_name
        player.position = edited_positon
        player.number = edited_number
        player.height = edited_height
        player.weight = edited_weight
        player.endurance = edited_endurance
        player.speed = edited_speed
        player.rush_with_ball = edited_rush_with_ball
        player.pass_ball = edited_pass_ball
        player.shoot = edited_shoot
        player.defence = edited_defence
        player.age = edited_age
        player.foot = edited_foot
        db.session.commit()
        flash('修改成功！')
        return redirect(url_for('index'))
    return render_template('editplayer.html', player=player)


@app.route('/player/delete/<int:player_id>', methods=['POST'])  # 限定只接受 POST 请求
@login_required  # 用于视图保护
@admin_permission.require(http_exception=403)  # 管理员权限保护
def delete(player_id):
    player = Players.query.get_or_404(player_id)  # 获取球员记录
    db.session.delete(player)  # 删除对应的记录
    db.session.commit()  # 提交数据库会话
    flash('球员删除成功')
    return redirect(url_for('index'))  # 重定向回主页


@app.route('/addplayer', methods=['GET', 'POST'])
@login_required  # 用于视图保护
@admin_permission.require(http_exception=403)  # 管理员权限保护
def add():
    if request.method == 'POST':
        playername = request.form.get('add_playername')
        position = request.form.get('add_position')
        number = request.form.get('add_number')
        edited_height = request.form.get('add_height')
        edited_weight = request.form.get('add_weight')
        edited_endurance = request.form.get('add_endurance')
        edited_speed = request.form.get('add_speed')
        edited_rush_with_ball = request.form.get('add_rush_with_ball')
        edited_pass_ball = request.form.get('add_pass_ball')
        edited_shoot = request.form.get('add_shoot')
        edited_defence = request.form.get('add_defence')
        edited_age = request.form.get('add_age')
        edited_foot = request.form.get('add_foot')
        exist_number = Players.query.filter_by(number=number).all()
        if exist_number:
            flash("号码重复了！！！")
        else:
            player_add1 = Players(playername, position, number, edited_age, edited_height, edited_weight, edited_foot,
                                  edited_endurance, edited_speed, edited_rush_with_ball, edited_shoot, edited_defence,
                                  edited_pass_ball)
            db.session.add(player_add1)
            db.session.commit()  # 提交数据库参数
            flash("新球员添加成功")  # 成功提示
            return redirect(url_for('index'))
    return render_template('addplayer.html')


def is_detail(player):
    if player.height is None or player.weight is None or player.endurance is None or player.speed is None or player.rush_with_ball is None:
        return True
    else:
        return False


@app.route('/player/detail/<int:player_id>')
@login_required  # 用于视图保护
def detail(player_id):
    player = Players.query.get_or_404(player_id)
    if is_detail(player):
        flash("您还没有为该球员添加详细信息！！！请先添加！！")
        return redirect(url_for('index'))
    else:
        return render_template('Detial.html', player=player)


@app.route('/compare', methods=['GET', 'POST'])
@login_required  # 用于视图保护
def comparePage():
    if request.method == 'POST':
        player1_number = request.form.get('compare_number1')
        player2_number = request.form.get('compare_number2')
        return redirect(url_for('compare_two', player1_number=player1_number, player2_number=player2_number))
    return render_template('ComparePage.html')


@app.route('/compareTwo/<int:player1_number>/to/<int:player2_number>')
@login_required  # 用于视图保护
def compare_two(player1_number, player2_number):
    player1 = Players.query.filter_by(number=player1_number).first()
    player2 = Players.query.filter_by(number=player2_number).first()
    return render_template('compare_two.html', player1=player1, player2=player2)


# 自定义404页面，提示用户路由输入错误
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# 自定义403页面,提示用户越权访问
@app.errorhandler(403)
def right_not_enough(e):
    return render_template('403.html'), 403


@app.route('/writerPage')
def writerPage():
    return render_template('WriterPage.html')
