from pathlib import Path

import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode

def create_bar_chart(data, title):
    color_scale = alt.Scale(domain=["informational", "low", "medium", "high", "critical"],
                            range=["#00FFFF", "#00FF00", "#FFFF00", "#FFAF00", "#FF0000"])
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Level", sort=["critical", "high", "medium", "low", "informational"]),
        y=alt.Y("Value", scale=alt.Scale(domain=(0, 1000))),
        color=alt.Color("Level", scale=color_scale)
    ).properties(
        width=300,
        height=400,
        title=title
    )
    return chart

### Title and SelectBox
st.set_page_config(page_title='Comparison of Baseline Guides for Event Log Audit Settings',  layout='wide')
st.markdown("<h1 style='text-align: center;'>Comparison of Baseline Guides for Event Log Audit Settings</h1>", unsafe_allow_html=True)
selected_guide = st.selectbox('', ["Windows Default", "YamatoSecurity", "Australian Signals Directorate", "Microsoft(Server)", "Microsoft(Client)"], index=0, label_visibility="collapsed")
data_path = Path("./data") / selected_guide.replace(" ", "_").replace("(", "_").replace(")", "")
guide_link  = {
    "Windows Default": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "YamatoSecurity": "https://github.com/Yamato-Security/EnableWindowsLogSettings",
    "Australian Signals Directorate": "https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding",
    "Microsoft(Server)": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "Microsoft(Client)": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
}

### Audit settings
m1, m2, = st.columns((3, 2))
with m1:
    st.markdown(f"<h3 style='text-align: center;'>{selected_guide} Audit Settings</h3>", unsafe_allow_html=True)
    st.markdown(f"<p style='text-align: center;'><a href='{guide_link[selected_guide]}' target='_blank'>{guide_link[selected_guide]}</a></p>", unsafe_allow_html=True)
    csv_file = data_path.joinpath("WELA-Audit-Result.csv")
    df = pd.read_csv(csv_file)
    columns_to_display = [0, 1, 6, 5, 7, 2]
    df = df.iloc[:, columns_to_display]
    cellStyle = JsCode(
        r"""
        function(cellClassParams) {
             if (cellClassParams.data.DefaultSetting == "No Auditing") {
                if (cellClassParams.data.RecommendedSetting === null || cellClassParams.data.RecommendedSetting == "No Auditing") {
                    return {'background-color': 'lightgray'}
                } else if (cellClassParams.data.RecommendedSetting) {
                    return {'background-color': 'yellow'}
                }
             } else {
                return {'background-color': 'palegreen'}
             }
        }
       """)

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_column("Category", pinned="left", width=150)
    gb.configure_column("SubCategory", pinned="left", width=150)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle
    AgGrid(data=df, gridOptions=go, allow_unsafe_jscode=True, key='grid1', editable=True)

with m2:
    st.markdown(f"<h3 style='text-align: center;'>Log File Size Settings</h3>", unsafe_allow_html=True)
    msg = "TBD"
    if selected_guide == "YamatoSecurity" or selected_guide == "Australian Signals Directorate":
        msg = f"The following table shows the recommended settings for log file size, based on the {selected_guide} guide."
    else:
        msg = f"{selected_guide} does not include any recommended settings regarding log size."
    st.markdown(f"<p style='text-align: center;'>{msg}</p>", unsafe_allow_html=True)
    csv_file = data_path.joinpath("WELA-FileSize-Result.csv")
    df = pd.read_csv(csv_file)
    columns_to_display = [0, 4, 3]
    df = df.iloc[:, columns_to_display]
    cellStyle = JsCode(
        r"""
        function(cellClassParams) {
             if (cellClassParams.data.Recommended === null ) {
                return {'background-color': `lightgray`}
             } else {
                return {'background-color': 'yellow'}
             }
        }
       """)

    gb = GridOptionsBuilder.from_dataframe(df)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key="log_file_size", editable=True)


### Sigma Rule Statistics
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>Statistics on Usable and Unusable Sigma Rule(hayabusa rule)</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>The following graph shows the detectability of Sigma rules based on the selected Audit Guide.</p>", unsafe_allow_html=True)

level_order = ["critical", "high", "medium", "low", "informational"]
df_usable = pd.read_csv(data_path.joinpath("UsableRules.csv"))
df_unusable = pd.read_csv(data_path.joinpath("UnusableRules.csv"))
m1, m2, = st.columns(2)
with m1:
    df_usable["level"] = pd.Categorical(df_usable["level"], categories=level_order, ordered=True)
    df_usable.sort_values("level", inplace=True)
    data = df_usable["level"].value_counts().reindex(level_order).reset_index()
    data.columns = ["Level", "Value"]
    total = data["Value"].sum()

    ## Bar chart
    st.markdown(f"<h3 style='text-align: center;'>Usable Rules (Total: {total})</h3>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(data, ""), use_container_width=True)

    ## List
    st.markdown(f"<h3 style='text-align: center;'>Usable Rules List (Total: {total})</h3>", unsafe_allow_html=True)
    cellStyle_unusable = JsCode(
        r"""
        function(cellClassParams) {
            return {'background-color': 'lightcyan'}
        }
        """
    )
    gb = GridOptionsBuilder.from_dataframe(df_usable)
    gb.configure_column("title", pinned="left", width=150)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle_unusable
    AgGrid(df_usable, gridOptions=go, allow_unsafe_jscode=True, key='usable_rules', editable=True)


with m2:
    df_unusable["level"] = pd.Categorical(df_unusable["level"], categories=level_order, ordered=True)
    df_unusable.sort_values("level", inplace=True)
    data = df_unusable["level"].value_counts().reindex(level_order).reset_index()
    data.columns = ["Level", "Value"]
    total = data["Value"].sum()

    ## Bar chart
    st.markdown(f"<h3 style='text-align: center;'>Unusable Rules (Total: {total})</h3>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(data, ""), use_container_width=True)

    ## List
    st.markdown(f"<h3 style='text-align: center;'>Unusable Rules List (Total: {total})</h3>", unsafe_allow_html=True)
    cellStyle_unusable = JsCode(
        r"""
        function(cellClassParams) {
            return {'background-color': 'gold'}
        }
        """
    )
    gb = GridOptionsBuilder.from_dataframe(df_unusable)
    gb.configure_column("title", pinned="left", width=150)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle_unusable
    AgGrid(df_unusable, gridOptions=go, allow_unsafe_jscode=True, key='un_usable_rules', editable=True)

m1, m2, m3, m4 = st.columns(4)
with m1:
    data = df_usable["service"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="service", title="", color_discrete_sequence=px.colors.qualitative.D3)
    st.markdown(f"<h4 style='text-align: center;'>Usable Service (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="usable_service")

with m2:
    data = df_usable["category"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="category", title="", color_discrete_sequence=px.colors.qualitative.D3)
    st.markdown(f"<h4 style='text-align: center;'>Usable Category (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="usable_category")

with m3:
    data = df_unusable["service"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="service", title="", color_discrete_sequence=px.colors.sequential.Sunset)
    st.markdown(f"<h4 style='text-align: center;'>Unusable Service (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="unusable_service")

with m4:
    data = df_unusable["category"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="category", title="", color_discrete_sequence=px.colors.sequential.Sunset)
    st.markdown(f"<h4 style='text-align: center;'>Unusable Category (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="unusable_cateogry")
