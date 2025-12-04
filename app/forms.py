from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email

class AccessRequestForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    reason = TextAreaField("Reason for Access", validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField("Submit Request")
