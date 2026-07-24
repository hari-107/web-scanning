from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("scan/start/", views.start, name="start_scan"),
    path("scan/<int:pk>/progress/", views.scan_progress, name="scan_progress"),
    path("scan/<int:pk>/status/", views.scan_status, name="scan_status"),
    path("scan/<int:pk>/report/", views.report, name="report"),
    path("scan/<int:pk>/pdf/", views.download_pdf, name="download_pdf"),
    path("scan/<int:pk>/rescan/", views.rescan, name="rescan"),
    path("scan/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
    path("reports/", views.report_list, name="report_list"),
    path("compare/", views.compare, name="compare"),
]
