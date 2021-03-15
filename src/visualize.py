import plotly.io as pio
import pickle
import plotly.graph_objects as go
from plotly.subplots import make_subplots


def visualize(dicts: dict, out: str):
    key, val = list(dicts.items())[0]

    ######################################## Frequencies data

    x_chi_delta = dicts[key]['Frequencies']["plot_deltas"]['x']
    y1_chi_delta = dicts[key]['Frequencies']["plot_deltas"]['y1']
    y2_chi_delta = dicts[key]['Frequencies']["plot_deltas"]['y2']

    x_chi_length = dicts[key]['Frequencies']["plot_length"]['x']
    y1_chi_length = dicts[key]['Frequencies']["plot_length"]['y1']
    y2_chi_length = dicts[key]['Frequencies']["plot_length"]['y2']

    x_chi_number = dicts[key]['Frequencies']["plot_packet_number"]['x']
    y1_chi_number = dicts[key]['Frequencies']["plot_packet_number"]['y1']
    y2_chi_number = dicts[key]['Frequencies']["plot_packet_number"]['y2']

    ################################################### Cumulative Distribution Function data
    x_cdf_delta = dicts[key]['CDF']["plot_deltas"]['x']
    y1_cdf_delta = dicts[key]['CDF']["plot_deltas"]['y1']
    y2_cdf_delta = dicts[key]['CDF']["plot_deltas"]['y2']

    x_cdf_length = dicts[key]['CDF']["plot_length"]['x']
    y1_cdf_length = dicts[key]['CDF']["plot_length"]['y1']
    y2_cdf_length = dicts[key]['CDF']["plot_length"]['y2']

    x_cdf_number = dicts[key]['CDF']["plot_packet_number"]['x']
    y1_cdf_number = dicts[key]['CDF']["plot_packet_number"]['y1']
    y2_cdf_number = dicts[key]['CDF']["plot_packet_number"]['y2']

    fig = make_subplots(rows=1, cols=2,
                        subplot_titles=("Frequencies for original and augmented data",
                                        "Cumulative distributions for original and augmented data"))

    fig.add_trace(
        go.Scatter(
            x=x_chi_delta,
            y=y1_chi_delta,
            name="chi delta org",
            mode ='lines',
            marker_color="#2457BD",
        ),
        row=1, col=1
    )
    fig.add_trace(
        go.Scatter(
            x=x_chi_delta,
            y=y2_chi_delta,
            name="chi_delta_aug",
            marker_color="#F0B729",
        ),
        row=1, col=1
    )

    fig.add_trace(
        go.Scatter(
            x=x_cdf_delta,
            y=y1_cdf_delta,
            name="cdf delta org",
            mode='lines',
            marker_color="#2F4F4F",
        ),
        row=1, col=2
    )
    fig.add_trace(
        go.Scatter(
            x=x_cdf_delta,
            y=y2_cdf_delta,
            name="cdf delta aug",
            marker_color="crimson",
        ),
        row=1, col=2
    )

    fig.update_xaxes(title_text="Deltas in seconds", row=1, col=2)
    fig.update_xaxes(title_text="Deltas in seconds", row=1, col=1)
    fig.update_yaxes(title_text="Number of ", row=1, col=2)
    fig.update_yaxes(title_text="Frequencies", row=1, col=1)

    fig.update_layout(title_text="Comparing data:", height=700,
        updatemenus=[
            dict(
                type="buttons",
                direction="down",
                buttons=list(
                    [
                        dict(
                            label="Deltas",
                            method="update",
                            args=[{"y": [y1_chi_delta, y2_chi_delta, y1_cdf_delta, y2_cdf_delta],
                                   "x": [x_chi_delta, x_cdf_delta]}],
                        ),
                        dict(
                            label="Lengths",
                            method="update",
                            args=[{"y": [y1_chi_length, y2_chi_length, y1_cdf_length, y2_cdf_length],
                                   "x": [x_chi_length, x_cdf_length]}],
                        ),
                        dict(
                            label="Packet count by seconds",
                            method="update",
                            args=[{"y": [y1_chi_number, y2_chi_number, y1_cdf_number, y2_cdf_number],
                                   "x": [x_chi_number, x_cdf_number]}],
                        )
                    ]
                ),
            ),
        ]
    )

    fig.show()
    pio.write_html(fig, file=out, auto_open=True)
