"""URL configuration: exactly one route, the harness's protected operation."""

from __future__ import annotations

from django.urls import path

from . import views, wire

urlpatterns = [path(wire.INVOKE_PATH.removeprefix("/"), views.invoke)]
