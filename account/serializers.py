from rest_framework import serializers
from account.models import User
from account.models import Role
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class LogUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "name", "email", "password"]

        read_only_fields = [
            "is_active",
            "is_staff",
            "is_superuser",
            "last_login",
            "date_joined",
        ]

    def validate_email(self, value):
        return value.strip().lower()

    def create(self, validated_data):
        validated_data["role"] = Role.Roles.ADMIN
        user = User.objects.create_user(**validated_data)
        return user


class EmployeeUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "name", "email", "password"]
        read_only_fields = [
            "is_active",
            "is_staff",
            "is_superuser",
            "last_login",
            "date_joined",
            "role",
        ]

    def validate_email(self, value):
        return value.strip().lower()

    def create(self, validated_data):
        validated_data["role"] = Role.Roles.EMPLOYEE

        user = User.objects.create_user(**validated_data)

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=255)
    password = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ["email", "password"]


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email", "name", "username"]


class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=255, write_only=True, style={"input_type": "password"}
    )
    password2 = serializers.CharField(
        max_length=255, write_only=True, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = ["password", "password2"]

    def validate(self, attrs):
        user = self.context.get("user")
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError("Passwords do not match")
        user.set_password(attrs.get("password"))
        user.save()
        return attrs

    def create(self, validated_data):
        user = self.context.get("user")
        user.set_password(validated_data["password"])
        user.save()
        return user


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        try:
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uid = urlsafe_base64_encode(force_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                link = f"http://localhost:8000/api/reset-password/{uid}/{token}/"
                subject = "Reset Your Password"
                message = f"Click the link below to reset your password:\n{link}"
                from_email = settings.EMAIL_HOST_USER
                recipient_list = [user.email]

                send_mail(
                    subject=subject,
                    message=message,
                    from_email=from_email,
                    recipient_list=recipient_list,
                    fail_silently=False,
                )
                return attrs
            else:
                raise serializers.ValidationError("Email does not exist")
        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError("There was an error processing your request. Please try again.")


class UserResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, write_only=True, style={"input_type": "password"}
    )
    password2 = serializers.CharField(
        max_length=255, write_only=True, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = ["password", "password2"]

    def validate(self, attrs):
        uid = self.context.get("uid")
        token = self.context.get("token")
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError("Passwords do not match")
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Invalid Token Or Expired Token")

        user.set_password(attrs.get("password"))
        user.save()
        return attrs

    def create(self, validated_data):
        user = self.context.get("user")
        user.set_password(validated_data["password"])
        user.save()
        return user
