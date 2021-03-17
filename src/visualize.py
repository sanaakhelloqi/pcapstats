from jinja2 import Template
import json

try:
    import importlib.resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources


def visualize(dicts: dict, out: str):
    with pkg_resources.path('resources', "viz.j2") as file_:
        template = Template(file_.read_text())

    with pkg_resources.path("resources", "materialize.min.css") as matcss:
        materialize_css = matcss.read_text()

    with pkg_resources.path("resources", "materialize.min.js") as matjs:
        materialize_js = matjs.read_text()

    with pkg_resources.path("resources", "canvasjs.min.js") as canvasjs:
        canvas_js = canvasjs.read_text()

    dicts_js = "let dicts = " + json.dumps(dicts)

    rendered = template.render(dicts=dicts_js, materializecss=materialize_css, materializejs=materialize_js,
                          canvasjs=canvas_js)

    with open(out, "w") as fh:
        fh.write(rendered)
