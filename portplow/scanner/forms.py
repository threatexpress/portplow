from django.forms import Form, ModelForm
from django.forms.fields import TextInput, HiddenInput, CharField
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, Button, Field, Hidden
from crispy_forms.bootstrap import FormActions, AppendedText, TabHolder, Tab
from scanner.models import Scan, Profile


class ScanForm(ModelForm):

    start_date = CharField(widget=HiddenInput())
    stop_date = CharField(widget=HiddenInput())
    scan_range = CharField(
        label="Scan Range",
        widget=TextInput(attrs={'class': 'dtrange'})
    )

    def __init__(self, *args, **kwargs):
        super(ScanForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.help_text_inline = True
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.helper.layout = Layout(
            TabHolder(
                Tab('Details',
                    'name', 'profile', 'group', 'hosts'),
                Tab('Options',
                    'chunk_size', 'scanner_count',
                    'scan_hours',
                    'scan_range',
                    'start_date',
                    'end_date',
                    ),
                Tab('Deconfliction',
                    'deconfliction_message',
                    'htaccess')
            ),
            FormActions(
                Submit('create', 'Create Scan'),
                Button('cancel', 'Cancel')
            )

        )

    class Meta:
        model = Scan
        fields = ['name', 'hosts', 'profile', 'group', 'chunk_size', 'scanner_count', 'deconfliction_message',
                  'scan_hours', 'start_date', 'stop_date', 'htaccess']


class ProfileForm(ModelForm):

    command = CharField(
        label="Command Line",
        widget=TextInput(attrs={'class': ''})
    )

    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.helper.layout = Layout(
            'name',
            'tool',
            'command',
            'description',
            FormActions(
                Submit('add', 'Add Profile'),
                Button('cancel', 'Cancel')
            )
        )

    class Meta:
        model = Profile
        fields = ['name', 'tool', 'command', 'description']
