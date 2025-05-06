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

st.set_page_config(page_title='Comparison of Baseline Guides for Event Log Audit Settings',  layout='wide')
st.markdown("<h1 style='text-align: center;'>Comparison of Baseline Guides for Event Log Audit Settings</h1>", unsafe_allow_html=True)
guide_org = st.selectbox('', ["Windows Default", "YamatoSecurity", "Australian Signals Directorate", "Microsoft", "CIS"])
guide = guide_org.replace(" ", "-")

guide_link  = {
    "Windows Default": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "YamatoSecurity": "https://github.com/Yamato-Security/EnableWindowsLogSettings",
    "Australian Signals Directorate": "https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding",
    "Microsoft": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "CIS": ""
}
### Audit settings
m1, m2, = st.columns((3, 2))
with m1:
    st.markdown(f"<h2 style='text-align: center;'>{guide_org} Audit Settings</h2>", unsafe_allow_html=True)
    st.markdown(f"<p style='text-align: center;'><a href='{guide_link[guide_org]}' target='_blank'>{guide_link[guide_org]}</a></p>", unsafe_allow_html=True)
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
    st.markdown(f"<h2 style='text-align: center;'>Log File Size Settings</h2>", unsafe_allow_html=True)
    st.markdown(f"<p style='text-align: center;'>TBD</p>", unsafe_allow_html=True)
    csv_file = f"{guide}-WELA-FileSize-Result.csv"
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
st.markdown("<h2 style='text-align: center;'>Statistics on Usable and Unusable Sigma Rule(hayabusa rule)</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>The following graph shows the detectability of Sigma rules based on the selected Audit Guide.</p>", unsafe_allow_html=True)

level_order = ["critical", "high", "medium", "low", "informational"]
df_usable = pd.read_csv(f"{guide}-UsableRules.csv")
df_unusable = pd.read_csv(f"{guide}-UnusableRules.csv")
m1, m2, = st.columns(2)
with m1:
    df_usable["level"] = pd.Categorical(df_usable["level"], categories=level_order, ordered=True)
    df_usable = df_usable.sort_values("level")
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
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key='usable_rules', editable=True)


with m2:
    df_unusable["level"] = pd.Categorical(df_unusable["level"], categories=level_order, ordered=True)
    df_unusable = df_unusable.sort_values("level")
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
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key='un_usable_rules', editable=True)

m1, m2, m3, m4 = st.columns(4)
with m1:
    data = df_usable["service"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="service", title="")
    st.markdown(f"<h3 style='text-align: center;'>Usable Service (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="usable_service")

with m2:
    data = df_usable["category"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="category", title="")
    st.markdown(f"<h3 style='text-align: center;'>Usable Category (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="usable_category")

with m3:
    data = df_unusable["service"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="service", title="")
    st.markdown(f"<h3 style='text-align: center;'>Unusable Service (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="unusable_service")

with m4:
    data = df_unusable["category"].dropna()
    count = data.shape[0]
    fig = px.pie(data, names="category", title="")
    st.markdown(f"<h3 style='text-align: center;'>Unusable Category (Total:{count})</h3>", unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, key="unusable_cateogry")

st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Recommended Setting bat</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>The following bat file can be used to set the recommended settings.</p>", unsafe_allow_html=True)
st.code(r"""
wevtutil sl Security /ms:1073741824
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:1073741824
wevtutil sl "Windows PowerShell" /ms:1073741824
wevtutil sl PowerShellCore/Operational /ms:1073741824
::wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824

:: Set all other important logs to 128 MB. Increase or decrease to fit your environment.
wevtutil sl System /ms:134217728
wevtutil sl Application /ms:134217728
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Bits-Client/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /ms:134217728
wevtutil sl "Microsoft-Windows-NTLM/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/KernelMode" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
wevtutil sl "Microsoft-Windows-PrintService/Admin" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
wevtutil sl "Microsoft-Windows-PrintService/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-SmbClient/Security" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/MSI and Script" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Deployment" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Execution" /ms:134217728
wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Diagnosis-Scripted/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:134217728

:: Enable any logs that need to be enabled
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true

:: Enable PowerShell Module logging
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /f /t REG_DWORD /d 1
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames  /f /v ^* /t REG_SZ /d ^*

:: Enable PowerShell Script Block logging
reg add HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /f /t REG_DWORD /d 1

::
:: Configure Security log 
:: Note: subcategory IDs are used instead of the names in order to work in any OS language.

:: Account Logon
:::: Credential Validation
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Kerberos Authentication Service (disable for clients)
auditpol /set /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Kerberos Service Ticket Operations (disable for clients)
auditpol /set /subcategory:{0CCE9240-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Account Management
:::: Computer Account Management
auditpol /set /subcategory:{0CCE9236-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Account Management Events
auditpol /set /subcategory:{0CCE923A-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Security Group Management
auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: User Account Management
auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Detailed Tracking
:::: Plug and Play
auditpol /set /subcategory:{0cce9248-69ae-11d9-bed3-505054503030} /success:enable /failure:enable
:::: Process Creation
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Enable command line auditing (Detailed Tracking)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
:::: Process Termination (default: disabled)
:: auditpol /set /subcategory:{0CCE922C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: RPC Events
auditpol /set /subcategory:{0CCE922E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Audit Token Right Adjustments (default: disabled)
:: auditpol /set /subcategory:{0CCE924A-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: DS Access
:::: Directory Service Access (disable for clients)
auditpol /set /subcategory:{0CCE923B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Directory Service Changes (disable for clients)
auditpol /set /subcategory:{0CCE923C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Logon/Logoff
:::: Account Lockout
auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Group Membership (disabled due to noise)
:: auditpol /set /subcategory:{0CCE9249-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Logoff
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Logon
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Network Policy Server (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9243-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Logon/Logoff Events
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Special Logon
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Object Access
:::: Application Generated (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9222-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Certification Services (disable for client OSes)
auditpol /set /subcategory:{0CCE9221-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Detailed File Share (disabled due to noise)
:: auditpol /set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: File Share (disable if too noisy)
auditpol /set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: File System (disabled due to noise)
:: auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Connection (disable if too noisy)
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Packet Drop (disabled due to noise)
:: auditpol /set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Kernel Object (disabled due to noise)
:: auditpol /set /subcategory:{0CCE921F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Object Access Events
auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Registry (currently disabled due to noise)
:: auditpol /set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Removable Storage
auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: SAM
auditpol /set /subcategory:{0CCE9220-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Policy Change
:::: Audit Policy Change
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Authentication Policy Change
auditpol /set /subcategory:{0CCE9230-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Authorization Policy Change (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9231-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Policy Change (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: MPSSVC Rule-Level Policy Change (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9232-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Policy Change Events
auditpol /set /subcategory:{0CCE9234-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Privilege Use
:::: Sensitive Privilege Use (disable if too noisy)
auditpol /set /subcategory:{0CCE9228-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: System
:::: Other System Events (needs testing)
auditpol /set /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030} /success:disable /failure:enable
:::: Security State Change
auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Security System Extension
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: System Integrity
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
""")