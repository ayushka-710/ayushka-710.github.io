Project Title: User Authentication with Two-Factor Verification

Description:
This Django project implements user authentication with email verification and two-factor authentication (2FA) using a 
randomly generated code sent to the user's email. Users can reset their passwords through a secure link sent via email.

Features:
- User registration with email verification (can only use gmail account)
- User login with two-factor authentication
- Password reset functionality
- Email verification for account activation (can only use gmail account)
- Password strength validation
- User profile management

Prerequisites:
Before running this project, ensure you have the following installed on your system:
- Python 3.x
- Django 3.x or higher
- pip (Python package installer)
- A mail server setup 

Installation Instructions:
- Download the zip file containing the project.
- Extract the Zip File
- Extract the contents of the zip file to your desired location.
- Navigate to the Project Directory (cd <project_directory>)
- Activate the Virtual Environment (source venv/bin/activate   # On Windows use `venv\Scripts\activate`)
- Configure Email Settings
    - Open fassign/settings.py and set up the following:

        EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
        EMAIL_HOST = 'smtp.gmail.com'  # Or your email provider's SMTP server
        EMAIL_PORT = 587
        EMAIL_USE_TLS = True
        EMAIL_HOST_USER = 'your_email@gmail.com'  # Replace with your email if needed only.
        EMAIL_HOST_PASSWORD = 'your_email_password'  # Replace with your email password if needed only.

- Migrate Database (python manage.py migrate)
- Create a Superuser (python manage.py createsuperuser)
    - add username and password

- Run the Development Server (python manage.py runserver)

- Access the Application Open your web browser and navigate to http://127.0.0.1:8000/.



