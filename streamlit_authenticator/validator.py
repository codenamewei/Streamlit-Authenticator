import re

class Validator:
    """
    This class will check the validity of the entered username, name, and email for a 
    newly registered user.
    """
    def validate_username(self, username: str) -> bool:
        """
        Checks the validity of the entered username.

        Parameters
        ----------
        username: str
            The usernmame to be validated.
        Returns
        -------
        bool
            Validity of entered username.
        """
        pattern = r"^[a-zA-Z0-9_-]{1,20}$"
        return bool(re.match(pattern, username))

    def validate_name(self, name: str) -> bool:
        """
        Checks the validity of the entered name.
        
        Parameters
        ----------
        name: str
            The name to be validated.
        Returns
        -------
        bool
            Validity of entered name.
        """
        return 1 < len(name) < 100

    def validate_email(self, email: str) -> bool:
        """
        Checks the validity of the entered email.

        Parameters
        ----------
        email: str
            The email to be validated.
        Returns
        -------
        bool
            Validity of entered email.
        """
        return "@" in email and 2 < len(email) < 320

    def validate_password(self, password: str) -> bool:
        """
        Checks the validity of the entered email.

        Parameters
        ----------
        email: str
            The email to be validated.
        Returns
        -------
        bool
            Validity of entered email.
        """

        if not 8 < len(password) < 50:

            return False
        
        if not re.search('[A-Z]', password) or not re.search('[a-z]', password) or not re.search('[?,$#@%!]',password) or not re.search('[1234567890]', password):

            return False
        

        return True