import os

application = defines["app"]
app_name = os.path.basename(application)

format = "UDZO"
files = [application]
symlinks = {"Applications": "/Applications"}

background = "builtin-arrow"
window_rect = ((100, 100), (640, 280))
icon_size = 128
icon_locations = {
    app_name: (140, 120),
    "Applications": (500, 120),
}

show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
default_view = "icon-view"
show_icon_preview = False
