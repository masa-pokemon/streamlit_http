import streamlit as st
from scapy.all import sniff, TCP, IP
import pandas as pd
import threading
import time

# NOTE: This application requires root/administrator privileges on some systems
# to capture network packets. Also, on Windows, you will need to install
# Npcap first. You can install the required libraries with:
# pip install streamlit scapy pandas

# パケットキャプチャを実行する関数
def packet_capture_worker(packet_list, stop_event):
    """
    HTTPパケットをキャプチャし、リストに追加するワーカー関数。
    """
    def process_packet(packet):
        if packet.haslayer(TCP) and (packet.getlayer(TCP).dport == 80 or packet.getlayer(TCP).sport == 80 or packet.getlayer(TCP).dport == 443 or packet.getlayer(TCP).sport == 443):
            # HTTP/HTTPSトラフィックをフィルタリング
            try:
                # パケットから関連情報を抽出
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = str(packet[TCP].payload)
                
                # リストに新しいパケットを追加
                packet_list.append({
                    "時刻": time.strftime("%H:%M:%S", time.localtime()),
                    "送信元IP": src_ip,
                    "送信先IP": dst_ip,
                    "送信元ポート": src_port,
                    "送信先ポート": dst_port,
                    "ペイロード": payload
                })
            except IndexError:
                # IPまたはTCPレイヤーがないパケットを無視
                pass

    st.session_state.capture_thread_is_running = True
    # パケットキャプチャを開始
    # 'prn'は各パケットに対して呼び出される関数を指定します
    # 'stop_filter'はキャプチャを停止する条件を指定します
    sniff(
        prn=process_packet,
        filter="tcp and (port 80 or port 443)",
        store=0,
        stop_filter=lambda p: stop_event.is_set()
    )
    st.session_state.capture_thread_is_running = False

# StreamlitのUI設定
st.title("HTTP/HTTPS通信モニター")
st.markdown("下のボタンを使用してネットワークトラフィックのキャプチャを開始および停止します。")

# セッション状態を初期化
if 'is_running' not in st.session_state:
    st.session_state.is_running = False
if 'packets' not in st.session_state:
    st.session_state.packets = []
if 'capture_thread_is_running' not in st.session_state:
    st.session_state.capture_thread_is_running = False
if 'stop_event' not in st.session_state:
    st.session_state.stop_event = threading.Event()

# ボタンのロジック
if st.session_state.is_running:
    if st.button("キャプチャを停止"):
        st.session_state.stop_event.set()
        st.session_state.is_running = False
        st.info("キャプチャを停止しています...")
else:
    if st.button("キャプチャを開始"):
        st.session_state.is_running = True
        st.session_state.packets = []
        st.session_state.stop_event.clear()
        
        # ワーカーをスレッドで開始
        t = threading.Thread(
            target=packet_capture_worker, 
            args=(st.session_state.packets, st.session_state.stop_event),
            daemon=True
        )
        t.start()
        st.info("キャプチャを開始しました...HTTP/HTTPSトラフィックを監視しています。")

# キャプチャされたデータを表示
if st.session_state.packets:
    df = pd.DataFrame(st.session_state.packets)
    st.dataframe(df, use_container_width=True)
else:
    st.info("まだパケットはキャプチャされていません。")

st.markdown("""
<style>
.stButton>button {
    background-color: #4CAF50;
    color: white;
    padding: 10px 24px;
    border-radius: 8px;
    border: none;
    font-size: 16px;
    cursor: pointer;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}
.stButton>button:hover {
    background-color: #45a049;
}
</style>
""", unsafe_allow_html=True)
