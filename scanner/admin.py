from django.contrib import admin

from .models import (
    Cookie,
    Endpoint,
    Finding,
    Form,
    HttpHeader,
    LogLine,
    Port,
    Scan,
    Technology,
)


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    fields = ("severity", "title", "affected_url", "parameter", "detected_by")
    show_change_link = True


class PortInline(admin.TabularInline):
    model = Port
    extra = 0


class TechnologyInline(admin.TabularInline):
    model = Technology
    extra = 0


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "target_url",
        "status",
        "risk_rating",
        "security_score",
        "created_at",
    )
    list_filter = ("status", "risk_rating")
    search_fields = ("target_url", "hostname", "ip_address")
    date_hierarchy = "created_at"
    inlines = [FindingInline, PortInline, TechnologyInline]
    readonly_fields = ("created_at", "started_at", "finished_at")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "scan", "affected_url", "detected_by")
    list_filter = ("severity", "detected_by")
    search_fields = ("title", "affected_url", "parameter")


@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ("url", "method", "status_code", "source", "interesting")
    list_filter = ("interesting", "method", "status_code")
    search_fields = ("url",)


admin.site.register(Port)
admin.site.register(Technology)
admin.site.register(Form)
admin.site.register(HttpHeader)
admin.site.register(Cookie)
admin.site.register(LogLine)

admin.site.site_header = "Web Security Assessment Platform"
admin.site.site_title = "WebSec Admin"
admin.site.index_title = "Scan data administration"
