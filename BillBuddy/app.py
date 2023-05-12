from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import logout_user, LoginManager, UserMixin, login_user, current_user, login_required
import json
from flask import current_app
from flask_cors import CORS
from flask import Flask, render_template, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify
from flask_login import logout_user, LoginManager, UserMixin, login_user, current_user, login_required
from flask import current_app
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
import sqlite3
app = Flask(__name__)


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecretkey'

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def to_dict(self):
        return {'id': self.id,
                'username': self.username,
                'email': self.email}


class group_table(db.Model):
    group_id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(120), nullable=False)
    num_members = db.Column(db.Integer, nullable=False)


class UserGroup(db.Model):
    user_group_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey(
        'group_table.group_id'), nullable=False)


class Expense(db.Model):
    expense_id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey(
        'group_table.group_id'), nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(120), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')


class ExpenseSplit(db.Model):
    expense_split_id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey(
        'expense.expense_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')


with app.app_context():
    db.create_all()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error='Username already exists')
        if existing_email:
            return render_template('register.html', error='Email already exists')
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))


@app.route('/home')
@login_required
def home():
    user_groups = db.session.query(UserGroup).filter_by(
        user_id=current_user.id).all()
    groups = []
    for ug in user_groups:
        group = db.session.query(group_table).filter_by(
            group_id=ug.group_id).first()
        if group:
            groups.append({"name": group.group_name,
                          "num": group.num_members, "id": group.group_id})
    return render_template('home.html', user=current_user, groups=groups)


@app.route('/group_<string:group_id>')
@login_required
def group(group_id):

    grp_id = int(group_id)
    group_name = db.session.query(group_table.group_name).filter_by(
        group_id=grp_id).first()[0]

    expenses = db.session.query(Expense).filter_by(group_id=grp_id).all()
    transactions = []
    for expense in expenses:
        user = db.session.query(User).filter_by(id=expense.payer_id).first()
        print(current_user.id)
        print(expense.payer_id)
        type = "NEED TO BE PAID" if expense.payer_id == current_user.id else "NEED TO PAY"
        print(expense.status)
        emperical_type = expense.status
        expense_split = ExpenseSplit.query.filter_by(
            expense_id=expense.expense_id, user_id=current_user.id).first()
        status = "not paid" if expense_split.status == "unpaid" else "paid"
        transactions.append({"emp_status": emperical_type, "name": expense.description, "id": expense.expense_id,
                            "user": user.username, "type": type, "status": status})

    user_groups = db.session.query(UserGroup).filter_by(group_id=grp_id).all()
    members = []
    for user_group in user_groups:
        user = db.session.query(User).filter_by(id=user_group.user_id).first()
        members.append(user.username)

    return render_template("grp_page.html", group_name=group_name, transactions=transactions, members=members)


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    description = request.form['description']
    amount = float(request.form['amount'])
    group_name = request.form['group_name']
    # Get group id
    conn = sqlite3.connect('instance/database.db')
    c = conn.cursor()
    c.execute("SELECT group_id FROM group_table WHERE group_name=?", (group_name,))
    group_id = c.fetchone()[0]

    # Get users in the group
    c.execute("SELECT user_id FROM user_group WHERE group_id=?", (group_id,))
    user_ids = [row[0] for row in c.fetchall()]
    num_users = len(user_ids)

    # Calculate split amount
    split_amount = round(amount / num_users, 2)

    # Insert expense data
    c.execute("INSERT INTO expense (group_id, payer_id, description, total_amount, status) VALUES (?, ?, ?, ?, ?)",
              (group_id, current_user.id, description, amount, 'unpaid'))
    expense_id = c.lastrowid

    # Insert expense split data for each user
    for user_id in user_ids:
        c.execute("INSERT INTO expense_split (expense_id, user_id, amount, status) VALUES (?, ?, ?, ?)",
                  (expense_id, user_id, split_amount, 'unpaid'))

    # Update group total expense
    # c.execute("UPDATE group_table SET total_amount=total_amount+? WHERE group_id=?", (amount, group_id))
    c.execute("UPDATE expense_split SET status='paid' WHERE expense_id=? AND user_id=?",
              (expense_id, current_user.id))
    conn.commit()
    conn.close()

    user_groups = db.session.query(UserGroup).filter_by(
        user_id=current_user.id).all()
    groups = []
    for ug in user_groups:
        group = db.session.query(group_table).filter_by(
            group_id=ug.group_id).first()
        if group:
            groups.append({"name": group.group_name,
                          "num": group.num_members, "id": group.group_id})
    return render_template('home.html', user=current_user, groups=groups)


@app.route('/transaction_<string:transaction_id>')
@login_required
def transaction(transaction_id):
    # transaction = "t1"
    # user = "u1"
    # members = [{"name": "mem1", "status": "paid"},
    #            {"name": "mem2", "status": "not paid"},
    #            {"name": "mem3", "status": "paid"},
    #            {"name": "mem4", "status": "not paid"},
    #            {"name": "mem5", "status": "paid"},
    #            {"name": "mem6", "status": "not paid"}]
    # value = 100  # each person's share aka total/no of ppl

    trans_id = int(transaction_id)
    exp = db.session.query(Expense).filter_by(
        expense_id=trans_id).first()
    trans_name = exp.description
    userid = exp.payer_id
    user = db.session.query(User).filter_by(id=userid).first().username
    value = exp.total_amount
    grpid = exp.group_id
    value = value / \
        db.session.query(group_table).filter_by(
            group_id=grpid).first().num_members

    members = []
    splits = db.session.query(
        ExpenseSplit).filter_by(expense_id=trans_id)
    for i in splits:
        name_id = i.user_id
        name = db.session.query(User).filter_by(id=name_id).first().username
        stat = i.status
        if stat == "unpaid":
            stat = "not paid"
        else:
            stat = "paid"
        if name_id == userid:
            stat = "paid"
        members.append({"name": name, "status": stat})
    trans_json = json.dumps(members)
    return render_template("transaction_page.html", transaction=trans_name, user=user, members=members, value=value, trans_json=trans_json)


@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        group_name = request.json['group_name']
        member_names = request.json['participants']
        num_members = len(member_names)

        new_group = group_table(group_name=group_name, num_members=num_members)
        db.session.add(new_group)
        db.session.commit()
        group_id = new_group.group_id

        for member_name in member_names:
            user = db.session.query(User).filter_by(id=member_name).first()
            if user is None:
                return jsonify({'error': 'User {} not found'.format(member_name)})
            user_id = user.id
            new_user_group = UserGroup(user_id=user_id, group_id=group_id)
            db.session.add(new_user_group)
            db.session.commit()
        return jsonify({'group_id': group_id, 'group_name': group_name, 'num_members': num_members, 'members': member_names})
    else:
        users = User.query.all()
        users = [u.to_dict() for u in users]
        current_user_id = current_user.id
        return render_template('create_group.html', users=users, current_user_id=current_user_id)


@app.route('/remove_group/<int:group_id>', methods=['POST'])
def remove_group(group_id):
    # Delete the UserGroup objects associated with the group
    UserGroup.query.filter_by(group_id=group_id).delete()

    # Delete the ExpenseSplit objects associated with the Expenses in the group
    expense_ids = [expense.expense_id for expense in Expense.query.filter_by(
        group_id=group_id).all()]
    ExpenseSplit.query.filter(ExpenseSplit.expense_id.in_(
        expense_ids)).delete(synchronize_session=False)

    # Delete the Expenses in the group
    Expense.query.filter_by(group_id=group_id).delete()

    # Delete the Group object
    group = group_table.query.get_or_404(group_id)
    db.session.delete(group)

    # Commit the changes to the database
    db.session.commit()

    # Return a success message
    return jsonify({'success': True})


@app.route('/mark_paid/<int:transaction_id>')
def mark_paid(transaction_id):
    # Find the ExpenseSplit ID for the given Expense ID and the current user ID
    expense_split = ExpenseSplit.query.filter_by(
        expense_id=transaction_id, user_id=current_user.id).first()

    if expense_split:
        # If an ExpenseSplit is found, mark it as paid
        expense_split.status = 'paid'
        db.session.commit()
        expenses_split = ExpenseSplit.query.filter_by(
            expense_id=transaction_id).all()
        count = 0
        print(expenses_split)
        for expense_split in expenses_split:
            if expense_split.status == 'unpaid':
                count = count + 1
        print(count)
        if count == 0:
            dummy = Expense.query.filter_by(expense_id=transaction_id).first()
            print(dummy)
            print(dummy.status)
            dummy.status = 'paid'
        db.session.commit()
        # Return a success message
        return jsonify({'success': True})
    else:
        # If no ExpenseSplit is found, return an error message
        return jsonify({'success': False, 'message': 'ExpenseSplit not found'})


@app.route('/delete/<int:expense_id>')
def deletetransac(expense_id):
    # Delete from expense table
    num_expenses_deleted = db.session.query(
        Expense).filter_by(expense_id=expense_id).delete()
    # Delete from expense_split table
    num_splits_deleted = db.session.query(
        ExpenseSplit).filter_by(expense_id=expense_id).delete()
    # Commit the changes to the database
    db.session.commit()
    return f"{num_expenses_deleted} expenses and {num_splits_deleted} splits deleted"

@app.route('/my_expenses')
@login_required
def expenses():
    expenses = ExpenseSplit.query.filter_by(user_id=current_user.id).all()
    expense_data = []
    for expense in expenses:
        prime_expenses = Expense.query.filter_by(expense_id=expense.expense_id).first()
        user_id = prime_expenses.payer_id
        if (user_id == current_user.id):
            continue
        user = User.query.filter_by(id=user_id).first()
        expense_data.append({'payable_to': user.username,
                             'description': prime_expenses.description,
                             'amount': expense.amount,
                             'status': expense.status})
    return render_template('my_expenses.html', expense_data=expense_data)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
if __name__ == '__main__':
    app.run(debug=True)
