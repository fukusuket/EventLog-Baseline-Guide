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
guid = st.selectbox('', ["Windows Default", "YamatoSecurity", "Microsoft", "ACSC", "AUD", "CIS"])
st.markdown(f"<h2 style='text-align: center;'> {guid} Audit Settings</h2>", unsafe_allow_html=True)
st.markdown(f"<p style='text-align: center;'>Please check audit setting!</p>", unsafe_allow_html=True)
csv_file = "WELA-Audit-Result.csv"
df = pd.read_csv(csv_file)
columns_to_display = [0, 1, 2, 5, 6, 7]
df = df.iloc[:, columns_to_display]
cellStyle = JsCode(
    r"""
    function(cellClassParams) {
         if (cellClassParams.data.Default == "No Auditing") {
            return {'background-color': 'lightsalmon'}
         } else {
            return {'background-color': 'palegreen'}
         }
    }
   """)

grid_builder = GridOptionsBuilder.from_dataframe(df)
grid_options = grid_builder.build()
grid_options['defaultColDef']['cellStyle'] = cellStyle
AgGrid(data=df, gridOptions=grid_options, allow_unsafe_jscode=True, key='grid1', editable=True)
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Statistics on Usable and Unusable Sigma Rule(hayabusa rule)</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>The following graph shows the detectability of Sigma rules based on the selected Audit Guide.</p>", unsafe_allow_html=True)
m1, m2, = st.columns(2)
level_order = ["critical", "high", "medium", "low", "informational"]
with m1:
    csv_file = "UsableRules.csv"
    df = pd.read_csv(csv_file)
    df["level"] = pd.Categorical(df["level"], categories=level_order, ordered=True)
    df = df.sort_values("level")
    data = df["level"].value_counts().reindex(level_order).reset_index()
    data.columns = ["Level", "Value"]
    total = data["Value"].sum()
    st.markdown(f"<h3 style='text-align: center;'>Usable Rules (Total: {total})</h3>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(data, ""), use_container_width=True)
    st.markdown(f"<h3 style='text-align: center;'>Usable Rules List (Total: {total})</h3>", unsafe_allow_html=True)
    cellStyle_unusable = JsCode(
        r"""
        function(cellClassParams) {
            return {'background-color': 'lightcyan'}
        }
        """
    )
    grid_builder_unusable = GridOptionsBuilder.from_dataframe(df)
    grid_options_unusable = grid_builder_unusable.build()
    grid_options_unusable['defaultColDef']['cellStyle'] = cellStyle_unusable
    AgGrid(df, gridOptions=grid_options_unusable, allow_unsafe_jscode=True, key='usable_rules', editable=True)

with m2:
    csv_file = "UnusableRules.csv"
    df = pd.read_csv(csv_file)
    df["level"] = pd.Categorical(df["level"], categories=level_order, ordered=True)
    df = df.sort_values("level")
    data = df["level"].value_counts().reindex(level_order).reset_index()
    data.columns = ["Level", "Value"]
    total = data["Value"].sum()
    st.markdown(f"<h3 style='text-align: center;'>Unusable Rules (Total: {total})</h3>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(data, ""), use_container_width=True)
    st.markdown(f"<h3 style='text-align: center;'>Unusable Rules List (Total: {total})</h3>", unsafe_allow_html=True)
    cellStyle_unusable = JsCode(
        r"""
        function(cellClassParams) {
            return {'background-color': 'gold'}
        }
        """
    )

    grid_builder_unusable = GridOptionsBuilder.from_dataframe(df)
    grid_options_unusable = grid_builder_unusable.build()
    grid_options_unusable['defaultColDef']['cellStyle'] = cellStyle_unusable
    AgGrid(df, gridOptions=grid_options_unusable, allow_unsafe_jscode=True, key='un_usable_rules', editable=True)

st.markdown("<hr>", unsafe_allow_html=True)
m1, m2, m3 = st.columns((1,3,1))
with m2:
    st.markdown("<h2 style='text-align: center;'>Evnet Log File Size Settings</h2>", unsafe_allow_html=True)
    st.markdown(
        "<p style='text-align: center;'>The following table shows the... </p>",
        unsafe_allow_html=True)
    csv_file = "WELA-FileSize-Result.csv"
    df = pd.read_csv(csv_file)
    columns_to_display = [0, 3, 4, 6, 7]
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

    grid_builder_unusable = GridOptionsBuilder.from_dataframe(df)
    grid_options_unusable = grid_builder_unusable.build()
    grid_options_unusable['defaultColDef']['cellStyle'] = cellStyle
    AgGrid(df, gridOptions=grid_options_unusable, allow_unsafe_jscode=True, key="log_file_size", editable=True)