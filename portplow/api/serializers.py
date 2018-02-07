from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group  # User,
from rest_framework import serializers
from rest_framework.reverse import reverse

from scanner.models import Scan, Scanner, Profile, Attachment, Job, JobLog

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    full_name = serializers.CharField(source='get_full_name', read_only=True)
    links = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', User.USERNAME_FIELD, 'full_name',
            'is_active', 'links', 'groups' )

    def get_links(self, obj):
        request = self.context['request']
        username = obj.get_username()
        return {
            'self': reverse('user-detail',
                kwargs={User.USERNAME_FIELD: username}, request=request),
            # 'tasks': '{}?assigned={}'.format(
            #     reverse('task-list', request=request), username)
        }


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('url', 'name')


class QueueSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = Job

    def get_status(self, obj):
        return obj.get_status_display()


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan


class ScannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scanner


class ProfileSerializer(serializers.ModelSerializer):

    # tool = serializers.SerializerMethodField()

    # def get_tool(self, obj):
    #     return obj.get_tool_display()

    class Meta:
        model = Profile


class ScannerBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scanner
        fields = ('ip', 'status')


class JobBasicSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = ('status', 'command', 'target_hosts')

    def get_status(self, obj):
        return obj.get_status_display()


class JobLogSerializer(serializers.ModelSerializer):
    scanner = ScannerBasicSerializer(many=False, read_only=True)
    job = JobBasicSerializer(many=False, read_only=True)

    class Meta:
        model = JobLog
        fields = ('id', 'scanner', 'start_time', 'end_time', 'return_code',
                  'parsed', 'attempt', 'job')


class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment


class DeconflictionSerializer(serializers.ListSerializer):

    pass
