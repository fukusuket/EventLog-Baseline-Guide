import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode

st.set_page_config(page_title='Comparison of Baseline Guides for Event Log Audit Settings',  layout='wide')
st.markdown("<h1 style='text-align: center;'>Comparison of Baseline Guides for Event Log Audit Settings</h1>", unsafe_allow_html=True)
guid = st.selectbox('', ["Windows Default", "YamatoSecurity", "Microsoft", "CIS", "ACSC", "AD"])
st.markdown(f"<h2 style='text-align: center;'> {guid} Audit Settings</h2>", unsafe_allow_html=True)
st.markdown(f"<p style='text-align: center;'>Please check setting!</p>", unsafe_allow_html=True)
csv_file = "WELA-Audit-Result.csv"
df = pd.read_csv(csv_file)
columns_to_display = [0, 1, 2, 5, 6, 7]
df = df.iloc[:, columns_to_display]
cellStyle = JsCode(
    r"""
    function(cellClassParams) {
         if (cellClassParams.data.DefaultSetting == "No Auditing") {
            return {'background-color': 'gold'}
         } else {
            return {'background-color': 'lightcyan'}
         }
        }
   """)

grid_builder = GridOptionsBuilder.from_dataframe(df)
grid_options = grid_builder.build()
grid_options['defaultColDef']['cellStyle'] = cellStyle
AgGrid(data=df, gridOptions=grid_options, allow_unsafe_jscode=True, key='grid1', editable=True)
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Sigma Rule Statics</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>This is a comparison of the number of Sigma rules that can be used for selected baseline guide.</p>", unsafe_allow_html=True)
m1, m2, = st.columns(2)
with m1:
    st.markdown("<h3 style='text-align: center;'>Usable Rules (1,000)</h3>", unsafe_allow_html=True)
with m2:
    st.markdown("<h3 style='text-align: center;'>Unusable Rules (1,455)</h3>", unsafe_allow_html=True)

color_scale = alt.Scale(domain=["information", "low", "medium", "high", "critical"],
                        range=["#00FFFF", "#00FF00", "#FFFF00", "#FFAF00", "#FF0000"])

def create_bar_chart(data, title):
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Level", sort=["critical", "high", "medium", "low", "information"]),
        y="Value",
        color=alt.Color("Level", scale=color_scale)
    ).properties(
        width=300,
        height=300,
        title=title
    )
    return chart

m1, m2 = st.columns(2)
level_order = ["critical", "high", "medium", "low", "informational"]
with m1:
    data1 = pd.DataFrame({
        "Level": ["information", "low", "medium", "high", "critical"],
        "Value": [10, 20, 30, 25, 15]
    })
    st.altair_chart(create_bar_chart(data1, ""), use_container_width=True)
    csv_file = "UsableRules.csv"
    df1 = pd.read_csv(csv_file)
    df1["level"] = pd.Categorical(df1["level"], categories=level_order, ordered=True)
    df1 = df1.sort_values("level")
    st.markdown("<h3 style='text-align: center;'>Usable Rules List</h3>", unsafe_allow_html=True)
    AgGrid(df1, key="A", editable=True)

with m2:
    data2 = pd.DataFrame({
        "Level": ["information", "low", "medium", "high", "critical"],
        "Value": [5, 15, 25, 35, 20]
    })
    st.altair_chart(create_bar_chart(data2, ""), use_container_width=True)
    csv_file = "UnusableRules.csv"
    df2 = pd.read_csv(csv_file)
    df2["level"] = pd.Categorical(df2["level"], categories=level_order, ordered=True)
    df2 = df2.sort_values("level")
    st.markdown("<h3 style='text-align: center;'>Unusable Rules List</h3>", unsafe_allow_html=True)
    AgGrid(df2, key="B", editable=True)

st.markdown("<hr>", unsafe_allow_html=True)
m1, m2, m3 = st.columns((1,11,1))
with m2:
    st.markdown("<h2 style='text-align: center;'>Evnet Log File Size</h2>", unsafe_allow_html=True)
    csv_file = "WELA-FileSize-Result.csv"
    df = pd.read_csv(csv_file)
    AgGrid(df, key="C")