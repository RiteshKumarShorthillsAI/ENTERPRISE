from django.db import models
from django.contrib.auth.models import User
# Create your models here.



class StorageBucket(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    base_url = models.URLField(blank=True)  
    description = models.TextField(blank=True)  
    order_by = models.CharField(max_length=100, blank=True)  

class StorageCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    storage = models.ForeignKey(StorageBucket, on_delete=models.CASCADE)

    provider = models.CharField(max_length=50) 
    access_key_id = models.CharField(max_length=200, blank=True)  
    secret_access_key = models.CharField(max_length=200, blank=True) 
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)


class UserVerification(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="signup_verification_ref",
        help_text="User ID reference",
    )
    verification_jwt = models.CharField(
        max_length=200, help_text="Verification code for user signup"
    )
    max_retry_count = models.IntegerField(default=3)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def haveRetryLimit(self) -> bool:
        try:
            if self.max_retry_count <= 0:
                return False
            self.max_retry_count -= 1
            return True
        except:
            raise Exception("Unable to authenticate your link, pls try again later.")
