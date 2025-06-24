import random
from django.views import View
import requests
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.urls import path
from django.http import HttpResponse
import re
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from fassign.settings import EMAIL_HOST_USER
from .models import UserProfile
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator

def two_factor_verification(request):
    if request.method == 'POST':
        two_factor_code = request.POST.get('two_factor_code')
        user_id = request.session.get('2fa_user_id')

        if user_id:
            user = get_object_or_404(User, id=user_id)
            profile = UserProfile.objects.get(user=user)

            if profile.is_two_factor_code_valid() and profile.two_factor_code == two_factor_code:
                login(request, user)
                del request.session['2fa_user_id']
                profile.two_factor_code = ''
                profile.save()

                return redirect('home')
            else:
                messages.error(request, "Invalid or expired 2FA code.")
    
    return render(request, 'two_factor_verification.html')

def generate_two_factor_code():
    return str(random.randint(100000, 999999))

def verify_email(request, token):
    try:
        profile = UserProfile.objects.get(verification_token=token)
        if profile.email_verified:
            messages.info(request, "Email is already verified.")
        else:
            profile.email_verified = True
            profile.verification_token = ''
            profile.save()
            messages.success(request, "Email verified successfully. You can now sign in.")
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid verification link.")
    
    return redirect('index')

def forgetpassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = get_random_string(32)
            user.userprofile.reset_token = token
            user.userprofile.save()
            reset_link = request.build_absolute_uri(f'/reset-password/{token}/')

            send_mail(
                'Reset Your Password',
                f'Click the following link to reset your password: {reset_link}',
                EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            messages.success(request, 'Password reset email sent. Click the following link to reset your password')
        except User.DoesNotExist:
            messages.error(request, 'User with this email does not exist.')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
    return render(request, 'forgetpassword.html')

def reset_password(request, token):
    try:
        profile = UserProfile.objects.get(reset_token=token)
    except UserProfile.DoesNotExist:
        messages.error(request, "Invalid reset link.")
        return redirect('index')

    if request.method == 'POST':
        password = request.POST.get('password').strip()
        confirm_password = request.POST.get('confirm_password').strip()

        if not password or not confirm_password:
            messages.error(request, "Both fields are required.")
            return render(request, 'reset-password.html', {'token': token})

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'reset-password.html', {'token': token})

        # Password strength validation
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
        if not re.match(password_regex, password):
            messages.error(request, "Password must contain at least 8 characters, including uppercase, lowercase, a digit, and a special character.")
            return render(request, 'reset-password.html', {'token': token})

        user = profile.user
        user.set_password(password)
        user.save()

        # Clear the reset token
        profile.reset_token = ''
        profile.save()

        messages.success(request, "Your password has been reset successfully. You can now log in.")
        return redirect('index')

    return render(request, 'reset-password.html', {'token': token})


@login_required(login_url='index') 
def home(request):
    return render(request, 'home.html')

def index(request):
    if request.method == 'POST':
        if 'sign_in' in request.POST:
            username = request.POST.get('username')
            password = request.POST.get('password')

            clientKey = request.POST.get('g-recaptcha-response')
            secretKey = '6Lf-fEYqAAAAAPzymlQ2ZSCbAJvgq0xrhjWxVroG'
            data = {
                'secret': secretKey,
                'response': clientKey
            }

            r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = r.json()

            if result.get('success'):
                # Retrieve the username and password, filtering out any empty values
                username = [u for u in request.POST.getlist('username') if u.strip()][0]  
                password = [p for p in request.POST.getlist('password') if p.strip()][0]  

            # Authenticate user
            if result.get('success'):
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    profile = UserProfile.objects.get(user=user)
                    if profile.email_verified:
                        # Generate a 2FA code
                        two_factor_code = generate_two_factor_code()
                        profile.two_factor_code = two_factor_code
                        profile.two_factor_code_created_at = timezone.now()
                        profile.save()

                         # Send the 2FA code to the user's email
                        send_mail(
                            'Your 2FA Code',
                            f'Your 2FA code is: {two_factor_code}',
                            'yourapp@example.com',
                            [user.email],
                            fail_silently=False,
                        )

                         # Redirect to the 2FA verification page
                        request.session['2fa_user_id'] = user.id
                        return redirect('two_factor_verification')
                    else:
                        messages.error(request, "Please verify your email before signing in.")
                else:
                    messages.error(request, "Invalid username or password.")
            else:
                messages.error(request, "Invalid reCAPTCHA. Please try again.")

            return render(request, 'index.html', {'tab': 'sign_in'})

        elif 'sign_up' in request.POST:
            username = request.POST.get('username')
            firstname = request.POST.get('firstname')
            lastname = request.POST.get('lastname')
            email = request.POST.get('email')
            password = request.POST.get('password')
            rpassword = request.POST.get('rpassword')

           # Check if the username is empty
            if not username:
                messages.error(request, "Username is required.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })
            
            # Check if the username is already taken
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists!")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })

            # Check if the first name is empty
            if not firstname:
                messages.error(request, "First name is required.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'lastname': lastname,
                    'email': email
                })

            # Check if the last name is empty
            if not lastname:
                messages.error(request, "Last name is required.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'email': email
                })

            # Check if the email is empty
            if not email:
                messages.error(request, "Email is required.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname
                })
            
             # Check if the email is valid
            email_regex = r'^[a-zA-Z0-9._%+-]+@(gmail\.com)$' 
            if not re.match(email_regex, email):
                messages.error(request, "Invalid email address.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
            })

            
            # Check if the email is already registered
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already registered. Choose another one.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })


            # Check if the password is empty
            password = password.strip()
            if not password:
                messages.error(request, "Password is required.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })
            
            password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
            if not re.match(password_regex, password):
                messages.error(request,"Password must contain 8 characters, uppercase, lowercase, digit, and a special character.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })
            
            # Check if the repeated password is empty
            rpassword = rpassword.strip()
            if not rpassword:
                messages.error(request, "Please confirm your password.")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })

            # Check if passwords match
            if password != rpassword:
                messages.error(request, "Passwords do not match!")
                return render(request, 'index.html', {
                    'tab': 'sign_up',
                    'username': username,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email
                })

            # Create the user
            user = User.objects.create_user(username=username, email=email, password=password, first_name=firstname, last_name=lastname)
            profile = UserProfile.objects.create(user=user, email_verified=False)

            # Generate a verification token
            token = get_random_string(32)
            profile.verification_token = token
            profile.save()

            # Send verification email
            verification_link = request.build_absolute_uri(f'/verify-email/{token}/')
            send_mail(
                'Email Verification', f'Please verify your email by clicking the following link: {verification_link}',
                'ashutoshkharel777@gmail.com',
                [email],
                fail_silently=False,
            )

            messages.success(request, "Successfully registered! Please check your email to verify your account.")
            return redirect('index')

    return render(request, 'index.html', {'tab': 'sign_up'})

# Sign out view
def signout(request):
    logout(request)
    messages.success(request, "Successfully logged out!")
    return redirect('index')