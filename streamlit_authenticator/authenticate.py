import jwt
import bcrypt
import streamlit as st
from datetime import datetime, timedelta
import extra_streamlit_components as stx

from .hasher import Hasher
from .validator import Validator
from .utils import generate_random_pw

from .exceptions import CredentialsError, ForgotError, RegisterError, ResetError, UpdateError
import requests
#!! BAD PRACTICE
BACKEND_URL = "http://localhost:8000"



class Authenticate:

    access_token = "access_token"
    refresh_token = "refresh_token"
    username_token = "LOGGEDIN_USERNAME"
    authentication_status = "AUTHENTICATION_STATUS"

    """
    This class will create login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, cookie_manager : stx.CookieManager, access_token_expiry_hours: float, refresh_token_expiry_hours: float = None):
        """
        Create a new instance of "Authenticate".

        """
        self.cookie_manager = cookie_manager
        self.access_token_expiry_hours = access_token_expiry_hours
        self.refresh_token_expiry_hours = refresh_token_expiry_hours

        st.session_state[self.authentication_status] = False
        
        self._check_cookie()

    def _set_access_token_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return datetime.now() + timedelta(hours=self.access_token_expiry_hours)
    
    def _set_refresh_token_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return datetime.now() + timedelta(hours=self.refresh_token_expiry_hours)

    def _check_cookie(self) -> bool:
        """
        Checks the validity of the reauthentication cookie.
        """

        if self.cookie_manager.get(self.access_token):
            st.session_state[self.authentication_status] = True

            return True
        else:
            st.session_state[self.authentication_status] = None
            return False

 
    def _check_credentials(self, inplace: bool=True) -> bool:
        """
        Checks the validity of the entered credentials.

        Parameters
        ----------
        inplace: bool
            Inplace setting, True: authentication status will be stored in session state, 
            False: authentication status will be returned as bool.
        Returns
        -------
        bool
            Validity of entered credentials.
        """
        """validate with backend"""
        loginurl = BACKEND_URL + "/v1/auth/session/login"
        response = requests.post(loginurl, data = dict(username = self.username, password = self.password.encode()))
        
        if response.ok:
            if inplace:
                
                
                responsebody = response.json()
                
                access_token_exp_date = self._set_access_token_exp_date()

                self.cookie_manager.set(cookie = self.access_token, val = responsebody[self.access_token], expires_at=access_token_exp_date)
                
                refresh_token_exp_date = self._set_refresh_token_exp_date()
                self.cookie_manager.set(self.refresh_token, responsebody[self.refresh_token], key = self.refresh_token, expires_at=refresh_token_exp_date)

                self.cookie_manager.set(cookie = self.username_token, key = self.username_token, val = self.username, expires_at=access_token_exp_date)#, key = self.access_token,  expires_at=access_token_exp_date)

                st.session_state[self.authentication_status] = True

                

                
            else:
                return True
        
        else:

            st.warning('Username/password is incorrect. Failed to login.', icon='⚠️')

            if inplace:

                
                st.session_state[self.authentication_status] = False
            else:
                return False
        
    def get_access_token(self) -> str | None:

        self._check_cookie()
        
        return self.cookie_manager.get(self.access_token)

    def login(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of the authenticated user.
        bool
            The status of authentication, None: no credentials entered, 
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        
        
        if not st.session_state[self.authentication_status]:
            self._check_cookie()
            if not st.session_state[self.authentication_status]:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')

                login_form.subheader(form_name)
                self.username = login_form.text_input("Username").lower()
                self.password = login_form.text_input('Password', type='password')

                if login_form.form_submit_button('Login'):

                    if not self.username or not self.password:

                        st.warning('Username and password cannot be left empty', icon='⚠️')

                    else:
                        self._check_credentials()


        return self.cookie_manager.get(self.username_token), st.session_state[self.authentication_status]


    # def logout(self, button_name: str, location: str='main', key: str=None):
    #     """
    #     Creates a logout button.

    #     Parameters
    #     ----------
    #     button_name: str
    #         The rendered name of the logout button.
    #     location: str
    #         The location of the logout button i.e. main or sidebar.
    #     """
    #     if location not in ['main', 'sidebar']:
    #         raise ValueError("Location must be one of 'main' or 'sidebar'")
    #     if location == 'main':
    #         if st.button(button_name, key):
    #             self.cookie_manager.delete(self.access_token)
    #             st.session_state['logout'] = True
    #             st.session_state['USERNAME'] = None
    #             st.session_state['AUTHENTICATION_STATUS'] = None
    #     elif location == 'sidebar':
    #         if st.sidebar.button(button_name, key):
    #             self.cookie_manager.delete(self.access_token)
    #             st.session_state['logout'] = True
    #             st.session_state['USERNAME'] = None
    #             st.session_state['AUTHENTICATION_STATUS'] = None

    def logout(self):
        st.session_state[self.authentication_status] = None
        
        self.cookie_manager.set(cookie = self.username_token, key = self.username_token, val = None)
        self.cookie_manager.delete(self.access_token)
        #self.cookie_manager.delete(self.refresh_token)
        

    def _update_password(self, username: str, password: str):
        """
        Updates credentials dictionary with user's reset hashed password.

        Parameters
        ----------
        username: str
            The username of the user to update the password for.
        password: str
            The updated plain text password.
        """
        self.credentials['usernames'][username]['password'] = Hasher([password]).generate()[0]

    def reset_password(self, username: str, form_name: str, location: str='main') -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        username: str
            The username of the user to reset the password for.
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        Returns
        -------
        str
            The status of resetting the password.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            reset_password_form = st.form('Reset password')
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password')
        
        reset_password_form.subheader(form_name)
        self.username = username.lower()
        self.password = reset_password_form.text_input('Current password', type='password')
        new_password = reset_password_form.text_input('New password', type='password')
        new_password_repeat = reset_password_form.text_input('Repeat password', type='password')

        if reset_password_form.form_submit_button('Reset'):
            if self._check_credentials(inplace=False):
                if len(new_password) > 0:
                    if new_password == new_password_repeat:
                        if self.password != new_password: 
                            self._update_password(self.username, new_password)
                            return True
                        else:
                            raise ResetError('New and current passwords are the same')
                    else:
                        raise ResetError('Passwords do not match')
                else:
                    raise ResetError('No new password provided')
            else:
                raise CredentialsError('password')
    
    def _register_credentials(self, username: str, name: str, password: str, email: str, preauthorization: bool):
        """
        Adds to credentials dictionary the new user's information.

        Parameters
        ----------
        username: str
            The username of the new user.
        name: str
            The name of the new user.
        password: str
            The password of the new user.
        email: str
            The email of the new user.
        preauthorization: bool
            The preauthorization requirement, True: user must be preauthorized to register, 
            False: any user can register.
        """
        if not self.validator.validate_username(username):
            raise RegisterError('Username is not valid')
        if not self.validator.validate_name(name):
            raise RegisterError('Name is not valid')
        if not self.validator.validate_email(email):
            raise RegisterError('Email is not valid')

        self.credentials['usernames'][username] = {'name': name, 
            'password': Hasher([password]).generate()[0], 'email': email}
        if preauthorization:
            self.preauthorized['emails'].remove(email)

    def register_user(self, form_name: str, location: str='main', preauthorization=True) -> bool:
        """
        Creates a register new user widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the register new user form.
        location: str
            The location of the register new user form i.e. main or sidebar.
        preauthorization: bool
            The preauthorization requirement, True: user must be preauthorized to register, 
            False: any user can register.
        Returns
        -------
        bool
            The status of registering the new user, True: user registered successfully.
        """
        if preauthorization:
            if not self.preauthorized:
                raise ValueError("preauthorization argument must not be None")
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_user_form.subheader(form_name)
        new_email = register_user_form.text_input('Email')
        new_username = register_user_form.text_input('USERNAME').lower()
        new_name = register_user_form.text_input('Name')
        new_password = register_user_form.text_input('Password', type='password')
        new_password_repeat = register_user_form.text_input('Repeat password', type='password')

        if register_user_form.form_submit_button('Register'):
            if len(new_email) and len(new_username) and len(new_name) and len(new_password) > 0:
                if new_username not in self.credentials['usernames']:
                    if new_password == new_password_repeat:
                        if preauthorization:
                            if new_email in self.preauthorized['emails']:
                                self._register_credentials(new_username, new_name, new_password, new_email, preauthorization)
                                return True
                            else:
                                raise RegisterError('User not preauthorized to register')
                        else:
                            self._register_credentials(new_username, new_name, new_password, new_email, preauthorization)
                            return True
                    else:
                        raise RegisterError('Passwords do not match')
                else:
                    raise RegisterError('Username already taken')
            else:
                raise RegisterError('Please enter an email, username, name, and password')

    def _set_random_password(self, username: str) -> str:
        """
        Updates credentials dictionary with user's hashed random password.

        Parameters
        ----------
        username: str
            Username of user to set random password for.
        Returns
        -------
        str
            New plain text password that should be transferred to user securely.
        """
        self.random_password = generate_random_pw()
        self.credentials['usernames'][username]['password'] = Hasher([self.random_password]).generate()[0]
        return self.random_password

    def forgot_password(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a forgot password widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot password form.
        location: str
            The location of the forgot password form i.e. main or sidebar.
        Returns
        -------
        str
            Username associated with forgotten password.
        str
            Email associated with forgotten password.
        str
            New plain text password that should be transferred to user securely.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form('Forgot password')
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form('Forgot password')

        forgot_password_form.subheader(form_name)
        username = forgot_password_form.text_input('USERNAME').lower()

        if forgot_password_form.form_submit_button('Submit'):
            if len(username) > 0:
                if username in self.credentials['usernames']:
                    return username, self.credentials['usernames'][username]['email'], self._set_random_password(username)
                else:
                    return False, None, None
            else:
                raise ForgotError('Username not provided')
        return None, None, None

    def _get_username(self, key: str, value: str) -> str:
        """
        Retrieves username based on a provided entry.

        Parameters
        ----------
        key: str
            Name of the credential to query i.e. "email".
        value: str
            Value of the queried credential i.e. "jsmith@gmail.com".
        Returns
        -------
        str
            Username associated with given key, value pair i.e. "jsmith".
        """
        for username, entries in self.credentials['usernames'].items():
            if entries[key] == value:
                return username
        return False

    def forgot_username(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a forgot username widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot username form.
        location: str
            The location of the forgot username form i.e. main or sidebar.
        Returns
        -------
        str
            Forgotten username that should be transferred to user securely.
        str
            Email associated with forgotten username.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_username_form = st.form('Forgot username')
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form('Forgot username')

        forgot_username_form.subheader(form_name)
        email = forgot_username_form.text_input('Email')

        if forgot_username_form.form_submit_button('Submit'):
            if len(email) > 0:
                return self._get_username('email', email), email
            else:
                raise ForgotError('Email not provided')
        return None, email

    def _update_entry(self, username: str, key: str, value: str):
        """
        Updates credentials dictionary with user's updated entry.

        Parameters
        ----------
        username: str
            The username of the user to update the entry for.
        key: str
            The updated entry key i.e. "email".
        value: str
            The updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials['usernames'][username][key] = value

    def update_user_details(self, username: str, form_name: str, location: str='main') -> bool:
        """
        Creates a update user details widget.

        Parameters
        ----------
        username: str
            The username of the user to update user details for.
        form_name: str
            The rendered name of the update user details form.
        location: str
            The location of the update user details form i.e. main or sidebar.
        Returns
        -------
        str
            The status of updating user details.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            update_user_details_form = st.form('Update user details')
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form('Update user details')
        
        update_user_details_form.subheader(form_name)
        self.username = username.lower()
        field = update_user_details_form.selectbox('Field', ['Name', 'Email']).lower()
        new_value = update_user_details_form.text_input('New value')

        if update_user_details_form.form_submit_button('Update'):
            if len(new_value) > 0:
                if new_value != self.credentials['usernames'][self.username][field]:
                    self._update_entry(self.username, field, new_value)
                    if field == 'name':
                            st.session_state['name'] = new_value
                            self.access_token_exp_date = self._set_access_token_exp_date()
                            self.token = self._token_encode()
                            self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_name_expiry_hours))
                    return True
                else:
                    raise UpdateError('New and current values are the same')
            if len(new_value) == 0:
                raise UpdateError('New value not provided')
