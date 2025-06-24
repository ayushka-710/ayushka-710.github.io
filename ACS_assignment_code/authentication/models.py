from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True, null=True)

    # Add fields for 2FA
    two_factor_code = models.CharField(max_length=6, blank=True, null=True)
    two_factor_code_created_at = models.DateTimeField(null=True, blank=True)

    reset_token = models.CharField(max_length=32, blank=True, null=True)

    def is_two_factor_code_valid(self):
        if self.two_factor_code_created_at:
            return (timezone.now() - self.two_factor_code_created_at) < datetime.timedelta(minutes=5)
        return False
    
  