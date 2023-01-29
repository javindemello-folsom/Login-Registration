from flask_app.config.mysqlconnection import connectToMySQL

import re
from flask import flash

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

class User:
    def __init__( self , data ):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']
        
    
    @classmethod
    def save(cls, data ):
        query = "INSERT INTO users ( first_name , last_name , email , password, created_at, updated_at ) VALUES ( %(fname)s , %(lname)s , %(email)s , %(password)s, NOW() , NOW() );"
        # data is a dictionary that will be passed into the save method from server.py
        return connectToMySQL('login_registration').query_db( query, data )
    
    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL("login_registration").query_db(query,data)
        # Didn't find a matching user
        if len(result) < 1:
            return False
        return cls(result[0])
    
    @staticmethod
    def validate_user( user ):
        is_valid = True
        num_count = 0
        upper_count = 0
        if not EMAIL_REGEX.match(user['email']):
            flash(u"Please enter a valid email address.", 'email')
            is_valid = False

        if len(user['fname']) < 2:
            is_valid = False
            flash(u'Please enter a first name.','fname')

        if len(user['lname']) < 2:
            is_valid = False
            flash(u'Please enter a last name.','lname')

        if len(user['password']) < 8:
            is_valid = False
            flash(u'Password must be at least 8 characters.','password')
            
        for i in user['password']:
            if i.isnumeric():
                num_count += 1
            if i.isupper():
                upper_count += 1
        
        if num_count < 1:
            is_valid = False
            flash(u'Password must include at least one number.','password')
            
        if upper_count < 1:
            is_valid = False
            flash(u'Password must include at least one upper case.','password')
            
        if user['password'] != user['confirm_password'] :
            is_valid = False
            flash(u'Passwords must match.','confirm_password')
            
        if user.get('agreements') != 'check':
            is_valid = False
            flash(u'Must agree to terms.','agreements')
            
        return is_valid
    
    
    
    
    
    
    
    
    @classmethod
    def get_one(cls, user_id):
        query = "SELECT * FROM users WHERE id = %(id)s"
        results = connectToMySQL('login_registration').query_db(query, {'id':user_id})
        # # print(results[0])
        user = cls(results[0])
        return user    
    
    @classmethod
    def update(cls, request_form_data):
        query = "UPDATE users  SET first_name = %(fname)s, last_name = %(lname)s, email = %(email)s, updated_at = NOW()  WHERE id = %(user_id)s"
        results = connectToMySQL('login_registration').query_db(query, request_form_data)
        return results
    
    @classmethod
    def delete(cls, user_id):
        query ="DELETE from users WHERE id = %(id)s"
        results = connectToMySQL('login_registration').query_db(query, {'id':user_id})
        return results
    
    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results = connectToMySQL('login_registration').query_db(query)
        users = []
        for user in results:
            users.append( cls(user) )
        return users