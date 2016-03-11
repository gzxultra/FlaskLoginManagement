"""
from datetime import datetime
from flask import render_template, session, redirect, url_for

from . import main
from .forms import NameForms
"""

from . import main


@main.route('/')
def index():
    return 'hello world'
