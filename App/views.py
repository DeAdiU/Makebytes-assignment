from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import SignUpForm

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, 'App/login.html', {'form': form})

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account created successfully.")
            return redirect('login')
    else:
        form = SignUpForm()
    return render(request, 'App/signup.html', {'form': form})

def forgot_password_view(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            form.save(request=request, email_template_name='auth_app/password_reset_email.html')
            messages.success(request, "Password reset link sent to your email.")
            return redirect('login')
    else:
        form = PasswordResetForm()
    return render(request, 'App/forgot_password.html', {'form': form})

@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Your password was successfully updated!")
            return redirect('dashboard')
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'App/change_password.html', {'form': form})

@login_required
def dashboard_view(request):
    return render(request, 'App/dashboard.html', {'username': request.user.username})

@login_required
def profile_view(request):
    return render(request, 'App/profile.html', {
        'user': request.user,
        'date_joined': request.user.date_joined,
        'last_login': request.user.last_login
    })

def logout_view(request):
    logout(request)
    return redirect('login')
