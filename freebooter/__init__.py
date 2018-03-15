from flask import Flask, render_template, flash, request, url_for, redirect, session
from wtforms import Form, BooleanField, TextField, PasswordField, validators
from passlib.hash import sha256_crypt
from dbconnect import connection
import gc
from functools import wraps

MAX_QN = 3

app = Flask(__name__)

attempted_username=''

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")


def logout_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash("You need to logout first!")
            return redirect(url_for('user'))
    return wrap


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash("Please Login to proceed")
            return redirect(url_for('login'))
    return wrap

@app.route('/')
def homepage():
    #flash("hello")
    return render_template("creativeindex0.html")

@app.route('/clues/')
@login_required
def clues():
    #flash("hello")
    clue_list = []
    try:
        c,conn = connection()
        cur_qn = session['cur_qn']
        cur_phase = session['cur_phase']
        clue_list = c.execute("SELECT * FROM clues WHERE qid = (%s) AND qn_phase = (%s)",(cur_qn,cur_phase))
        if int(clue_list)>0:
            clue_list = c.fetchall()
        return render_template("clues.html",clue_list = clue_list)
    except Exception as e:
        #flash(e)
        flash("Error!")
        return render_template("clues.html",clue_list = clue_list)
    return render_template("clues.html",clue_list = clue_list)




@app.route('/leaderboard/')
def leaderboard():
    lead = []
    try:
        c, conn = connection()
        lead = c.execute("SELECT * FROM users ORDER BY cur_qn DESC, time_last_qn ASC")
        #flash(lead)
        if int(lead)>0:
            #flash("lead")
            lead = c.fetchall()
        return render_template("leaderboard.html",lead = lead)

    except Exception as e:
        #flash(e)
        flash("Error!")
        return render_template("leaderboard.html", lead = lead)

    return render_template("leaderboard.html", lead = lead)


@app.route('/user/', methods=['GET', 'POST'])
@login_required
def user():
    error = ''
    username = session['username']
    cur_phase = session['cur_phase']
    cur_qn = session['cur_qn']
    #flash(username + str(cur_phase) + str(cur_qn))
    if cur_qn > MAX_QN:
        session['congo'] = True
        return redirect(url_for('congo'))
    try:
        c, conn = connection()
        if request.method == 'POST':
            q = c.execute("SELECT * FROM questions WHERE qid = (%s) AND qn_phase = (%s)",(cur_qn,cur_phase))
            if int(q)>0:
                db_ans = c.fetchone()[2]
                answer = request.form['answer']
                if answer == db_ans:
                    c.execute("UPDATE users SET cur_qn = cur_qn+1 WHERE username = (%s)",(session['username'],))
                    conn.commit()
                    cur_qn = cur_qn + 1
                    session['cur_qn'] = cur_qn
                    if cur_qn > MAX_QN:
                        session['congo'] = True
                        return redirect(url_for('congo'))
                    else:
                        pass
                    flash('Congratulations!')
                    return render_template("user.html",username = username ,cur_qn = cur_qn, cur_phase = cur_phase, error=error)
                else:
                    error = 'Wrong answer!'
                    return render_template("user.html", username = username,cur_qn = cur_qn, cur_phase = cur_phase, error=error)
        c.close()
        conn.close()
        gc.collect()
    except Exception as e:
        flash("Error!")
        #flash(e)
        return render_template("user.html", cur_qn = cur_qn, cur_phase = cur_phase, error=error)

    #flash('welcome')
    return render_template("user.html", cur_qn = cur_qn, cur_phase = cur_phase, error=error)


@app.route("/logout/")
@login_required
def logout():
    session.clear()
    #flash("Logged Out")
    gc.collect()
    return redirect(url_for('homepage'))

@app.route('/login/', methods=["GET","POST"])
def login():
    error = ''
    cur_qn = 0
    cur_phase = 0
    try:
        c, conn = connection()
        if request.method == 'POST':
            data = c.execute("SELECT * FROM users WHERE username = (%s)",(request.form['username'],))


            if int(data) > 0:
                det = c.fetchone()
                username = det[1]
                password = det[3]
                cur_qn = det[4]
                cur_phase = det[5]
                if sha256_crypt.verify(request.form['password'],password):
                    session['logged_in'] = True
                    session['username'] = request.form['username']
                    session['cur_qn'] = cur_qn
                    session['cur_phase'] = cur_phase
                    #flash('logged_in')
                    return redirect(url_for('user'))
                else:
                    error = 'Invalid Password!'
            else:
                error = 'Username does not exists! signup.'
        c.close()
        conn.close()
        gc.collect()

        return render_template("login.html", error=error)

    except Exception as e:
        flash("Error!")
        #flash(e)
        return render_template("login.html", error=error)


#class RegistrationForm(Form):
#    userid = TextField('userid', [validators.Length(min=4, max=20)])
#    name = TextField('name', [validators.Length(min=7, max=50)])
##                            validators.Required(),
#                            validators.EqualTo('confirm', message='Passwords must match')
#                            ])
#    confirm = PasswordField('Repeat Password')

@app.route('/congo/')
def congo():
    return render_template('congo.html')

@app.route('/signup/', methods=["GET","POST"])
@logout_required
def signup():
    error = ''
    try:
        if request.method == 'POST':
            username = request.form['username']
            name = request.form['name']
            password = request.form['password']
            repeat = request.form['repeat']
            c, conn = connection()
            if repeat <> password:
                error = 'Passwords do not match!'
                return render_template("signup.html", error=error)
            else:
                x = c.execute("SELECT * FROM users WHERE username = (%s)",(username,))
                if int(x) > 0:
                    error = 'Username already exists!'
                    return render_template("signup.html", error=error)
                else:
                    c.execute("INSERT INTO users (username, name, password, cur_qn, cur_phase) VALUES (%s,%s,%s,%s,%s)",
                    (username, name, sha256_crypt.encrypt(password), '1', '1'))
                    conn.commit()
                    #flash('logged in')
                    c.close()
                    conn.close()
                    gc.collect()
                    session['logged_in'] = True
                    session['username'] = username
                    session['cur_qn'] = 1
                    session['cur_phase'] = 1
                    return redirect(url_for('user'))
        c, conn = connection()
        return render_template("signup.html")
    except Exception as e:
        flash("Error!")
        return render_template("signup.html")



if __name__ == "__main__":
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.debug = True
    app.run(host = '0.0.0.0')
