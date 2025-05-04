import streamlit as st
import pandas as pd
import altair as alt
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

st.set_page_config(page_title='Comparison of Baseline Guides for Event Log Audit Settings',  layout='wide')
st.markdown("<h1 style='text-align: center;'>Comparison of Baseline Guides for Event Log Audit Settings</h1>", unsafe_allow_html=True)
guide_org = st.selectbox('', ["Windows Default", "YamatoSecurity", "Australian Signals Directorate", "Microsoft", "CIS"])
guide = guide_org.replace(" ", "")

### Audit settings
m1, m2, = st.columns((3, 2))
with m1:
    st.markdown(f"<h2 style='text-align: center;'> {guide_org} Audit Settings</h2>", unsafe_allow_html=True)
    csv_file = f"{guide}-WELA-Audit-Result.csv"
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
    st.markdown("<h2 style='text-align: center;'>Log File Size Settings</h2>", unsafe_allow_html=True)
    csv_file = f"{guide}-WELA-FileSize-Result.csv"
    df = pd.read_csv(csv_file)
    columns_to_display = [0, 4, 3, 7]
    df = df.iloc[:, columns_to_display]
    cellStyle = JsCode(
        r"""
        function(cellClassParams) {
             if (cellClassParams.data.CorrectSetting == "N") {
                return {'background-color': 'lightsalmon'}
             } else {
                return {'background-color': 'palegreen'}
             }
        }
       """)

    gb = GridOptionsBuilder.from_dataframe(df)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key="log_file_size", editable=True)


### Sigma Rule Statistics
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Statistics on Usable and Unusable Sigma Rule(hayabusa rule)</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>The following graph shows the detectability of Sigma rules based on the selected Audit Guide.</p>", unsafe_allow_html=True)
m1, m2, = st.columns(2)
level_order = ["critical", "high", "medium", "low", "informational"]
with m1:
    csv_file = f"{guide}-UsableRules.csv"
    df = pd.read_csv(csv_file)
    df["level"] = pd.Categorical(df["level"], categories=level_order, ordered=True)
    df = df.sort_values("level")
    data = df["level"].value_counts().reindex(level_order).reset_index()
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
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_column("title", pinned="left", width=150)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle_unusable
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key='usable_rules', editable=True)

with m2:
    csv_file = f"{guide}-UnusableRules.csv"
    df = pd.read_csv(csv_file)
    df["level"] = pd.Categorical(df["level"], categories=level_order, ordered=True)
    df = df.sort_values("level")
    data = df["level"].value_counts().reindex(level_order).reset_index()
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

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_column("title", pinned="left", width=150)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle_unusable
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key='un_usable_rules', editable=True)