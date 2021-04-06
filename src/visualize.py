from jinja2 import Template
import json

try:
    import importlib.resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources


def visualize(dicts: dict, out: str):
    with pkg_resources.path('resources', "viz.j2") as file_:
        template = Template(file_.read_text())

    with pkg_resources.path("resources", "vis.min.css") as viscss:
        vis_css = viscss.read_text()

    with pkg_resources.path("resources", "vis.min.js") as visjs:
        vis_js = visjs.read_text()

    with pkg_resources.path("resources", "app.css") as appcss:
        app_css = appcss.read_text()

    with pkg_resources.path("resources", "app.js") as appjs:
        app_js = appjs.read_text()

    with pkg_resources.path("resources", "canvasjs.min.js") as canvasjs:
        canvas_js = canvasjs.read_text()

    dicts_js = "let dicts = " + json.dumps(dicts)

    rendered = template.render(json_data=dicts_js, viscss=vis_css, visjs=vis_js, appcss=app_css, appjs=app_js,
                               canvasjs=canvas_js)

    with open(out, "w") as fh:
        fh.write(rendered)
