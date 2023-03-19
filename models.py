from django.db import models
from django.core.validators import FileExtensionValidator

class WordlistUpload(models.Model):
    file = models.FileField(validators=[FileExtensionValidator(allowed_extensions=["txt"])])
