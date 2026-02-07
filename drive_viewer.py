"""
Google Drive CSV Viewer - Streamlit App
Perplexity 분석 결과 CSV 파일 조회 도구 (Google 로그인 지원)
"""

import streamlit as st
import pandas as pd
import os
import re
from io import BytesIO
from collections import defaultdict

# 페이지 설정 (가장 먼저 호출되어야 함)
st.set_page_config(
    page_title="Perplexity 결과 뷰어",
    page_icon="chart-bar",
    layout="wide"
)

# Phosphor Icons CSS 로드
st.markdown("""
<link rel="stylesheet" href="https://unpkg.com/@phosphor-icons/web@2.1.1/src/regular/style.css" />
<style>
    .ph-icon {
        font-size: 1.2em;
        vertical-align: middle;
        margin-right: 4px;
    }
    .ph-icon-lg {
        font-size: 1.5em;
        vertical-align: middle;
        margin-right: 6px;
    }
</style>
""", unsafe_allow_html=True)


def icon(name, size=""):
    """Phosphor 아이콘 HTML 생성"""
    css_class = f"ph ph-{name} ph-icon{'-lg' if size == 'lg' else ''}"
    return f'<i class="{css_class}"></i>'

# Google Drive API
try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload
    import google_auth_oauthlib.flow
    GOOGLE_API_AVAILABLE = True
except ImportError as e:
    GOOGLE_API_AVAILABLE = False
    print(f"Import Error: {e}")  # 디버그용

# Google OAuth 설정
# 이 값들은 Google Cloud Console에서 생성한 OAuth 2.0 클라이언트 설정입니다
# 환경 변수나 secrets.toml에서 로드할 수 있습니다
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID", "") if hasattr(st, 'secrets') else os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET", "") if hasattr(st, 'secrets') else os.environ.get("GOOGLE_CLIENT_SECRET", "")

# REDIRECT_URI 자동 감지
def get_redirect_uri():
    """환경에 따라 리디렉트 URI 자동 결정"""
    # Streamlit Cloud 환경 감지
    if os.environ.get("STREAMLIT_SHARING_MODE") or os.environ.get("IS_STREAMLIT_CLOUD"):
        return st.secrets.get("REDIRECT_URI_CLOUD", "https://perplexity-viewer.streamlit.app")
    # secrets.toml에서 로드
    if hasattr(st, 'secrets') and "REDIRECT_URI" in st.secrets:
        return st.secrets["REDIRECT_URI"]
    # 환경 변수에서 로드
    if os.environ.get("REDIRECT_URI"):
        return os.environ["REDIRECT_URI"]
    # 기본값 (로컬)
    return "http://localhost:8501"

REDIRECT_URI = get_redirect_uri()

SCOPES = ['https://www.googleapis.com/auth/drive.readonly', 
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
          'openid']


def get_google_auth_url():
    """Google OAuth 인증 URL 생성"""
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = REDIRECT_URI
    
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    return auth_url, state, flow


def exchange_code_for_credentials(code, state):
    """인증 코드를 자격 증명으로 교환"""
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES,
        state=state
    )
    flow.redirect_uri = REDIRECT_URI
    flow.fetch_token(code=code)
    
    return flow.credentials


def get_user_info(credentials):
    """사용자 정보 가져오기"""
    from googleapiclient.discovery import build
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    return user_info


def get_drive_service(credentials):
    """Google Drive API 서비스 생성"""
    return build('drive', 'v3', credentials=credentials)


def list_csv_files(service, folder_id=None):
    """Google Drive에서 CSV 파일 목록 가져오기"""
    query = "mimeType='text/csv'"
    if folder_id:
        query += f" and '{folder_id}' in parents"
    
    results = service.files().list(
        q=query,
        pageSize=100,
        fields="files(id, name, modifiedTime, size)"
    ).execute()
    
    return results.get('files', [])


def find_folder_by_name(service, folder_name):
    """폴더 이름으로 폴더 ID 찾기"""
    query = f"mimeType='application/vnd.google-apps.folder' and name='{folder_name}' and trashed=false"
    
    results = service.files().list(
        q=query,
        pageSize=10,
        fields="files(id, name)"
    ).execute()
    
    files = results.get('files', [])
    if files:
        return files[0]['id']  # 첫 번째 매칭 폴더 반환
    return None


def download_file_as_dataframe(service, file_id):
    """Google Drive에서 파일 다운로드 후 DataFrame으로 변환"""
    request = service.files().get_media(fileId=file_id)
    file_buffer = BytesIO()
    downloader = MediaIoBaseDownload(file_buffer, request)
    
    done = False
    while not done:
        _, done = downloader.next_chunk()
    
    file_buffer.seek(0)
    return pd.read_csv(file_buffer)


def parse_filename(filename):
    """파일명에서 원본 파일명, 타입, 토큰 수 추출"""
    pattern = r'^(.+)_(paragraph|sentence)_(\d+)\.csv$'
    match = re.match(pattern, filename)
    
    if match:
        return {
            'source': match.group(1),
            'type': match.group(2),
            'tokens': int(match.group(3))
        }
    return None


def group_files_by_source(files):
    """소스 파일명별로 파일 그룹화"""
    groups = defaultdict(lambda: {'paragraph': None, 'sentence': None})
    
    for file in files:
        parsed = parse_filename(file['name'])
        if parsed:
            key = f"{parsed['source']}_{parsed['tokens']}"
            groups[key][parsed['type']] = file
            groups[key]['source'] = parsed['source']
            groups[key]['tokens'] = parsed['tokens']
    
    return dict(groups)


def display_dataframe_with_features(df, key_prefix):
    """DataFrame을 검색, 정렬, 필터링 기능과 함께 표시"""
    
    # 검색
    search_term = st.text_input("검색", key=f"{key_prefix}_search", placeholder="텍스트 검색...", label_visibility="visible")
    
    if search_term:
        mask = df.astype(str).apply(lambda x: x.str.contains(search_term, case=False, na=False)).any(axis=1)
        df = df[mask]
    
    # 정렬
    col1, col2 = st.columns([2, 1])
    with col1:
        sort_column = st.selectbox("정렬 기준", options=['없음'] + list(df.columns), key=f"{key_prefix}_sort")
    with col2:
        sort_order = st.radio("순서", ["오름차순", "내림차순"], key=f"{key_prefix}_order", horizontal=True)
    
    if sort_column != '없음':
        ascending = sort_order == "오름차순"
        df = df.sort_values(by=sort_column, ascending=ascending)
    
    # 필터링
    st.markdown("**필터링**")
    numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
    
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        filter_column = st.selectbox("필터 컬럼", options=['없음'] + numeric_cols, key=f"{key_prefix}_filter_col")
    
    if filter_column != '없음':
        min_val = float(df[filter_column].min())
        max_val = float(df[filter_column].max())
        
        with filter_col2:
            min_filter = st.number_input("최소값", value=min_val, key=f"{key_prefix}_min")
        with filter_col3:
            max_filter = st.number_input("최대값", value=max_val, key=f"{key_prefix}_max")
        
        df = df[(df[filter_column] >= min_filter) & (df[filter_column] <= max_filter)]
    
    # 결과 표시
    st.markdown(f"**결과: {len(df)}개 행**")
    st.dataframe(df, width="stretch", height=400)
    
    # 다운로드 버튼
    csv_buffer = BytesIO()
    df.to_csv(csv_buffer, index=False, encoding='utf-8-sig')
    csv_buffer.seek(0)
    
    st.download_button(
        label="CSV 다운로드",
        data=csv_buffer,
        file_name=f"{key_prefix}_filtered.csv",
        mime="text/csv",
        icon=":material/download:"
    )
    
    return df


def local_mode():
    """로컬 파일 시스템 모드"""
    st.sidebar.markdown(f"### {icon('folder-open')} 로컬 폴더 설정", unsafe_allow_html=True)
    
    folder_path = st.sidebar.text_input(
        "결과 폴더 경로",
        value="./results/tables",
        help="CSV 파일이 저장된 폴더 경로"
    )
    
    if not os.path.exists(folder_path):
        st.warning(f"폴더를 찾을 수 없습니다: {folder_path}")
        return
    
    # CSV 파일 목록 가져오기
    csv_files = []
    for filename in os.listdir(folder_path):
        if filename.endswith('.csv'):
            filepath = os.path.join(folder_path, filename)
            csv_files.append({
                'name': filename,
                'path': filepath,
                'size': os.path.getsize(filepath)
            })
    
    if not csv_files:
        st.info("CSV 파일이 없습니다.")
        return
    
    # 파일 그룹화
    groups = group_files_by_source(csv_files)
    
    if not groups:
        st.warning("파일명 패턴이 맞는 CSV 파일이 없습니다.")
        st.info("예상 패턴: `{filename}_paragraph_{token}.csv`, `{filename}_sentence_{token}.csv`")
        return
    
    # 사이드바에 파일 목록 표시
    st.sidebar.markdown(f"### {icon('file-text')} 파일 목록", unsafe_allow_html=True)
    selected_source = st.sidebar.selectbox(
        "분석 결과 선택",
        options=list(groups.keys()),
        format_func=lambda x: f"{groups[x].get('source', x)} (토큰: {groups[x].get('tokens', 'N/A')})"
    )
    
    if selected_source:
        group = groups[selected_source]
        
        st.markdown(f"## {icon('chart-bar', 'lg')} {group.get('source', selected_source)}", unsafe_allow_html=True)
        st.caption(f"목표 토큰 수: {group.get('tokens', 'N/A')}")
        
        tab1, tab2 = st.tabs(["문단 (Paragraph)", "문장 (Sentence)"])
        
        with tab1:
            if group['paragraph']:
                df_para = pd.read_csv(group['paragraph']['path'])
                display_dataframe_with_features(df_para, f"{selected_source}_para")
            else:
                st.info("문단 데이터가 없습니다.")
        
        with tab2:
            if group['sentence']:
                df_sent = pd.read_csv(group['sentence']['path'])
                display_dataframe_with_features(df_sent, f"{selected_source}_sent")
            else:
                st.info("문장 데이터가 없습니다.")


def google_drive_mode():
    """Google Drive 모드"""
    if not GOOGLE_API_AVAILABLE:
        st.error("""
        Google API 라이브러리가 설치되지 않았습니다.
        
        ```bash
        pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client
        ```
        """)
        return
    
    # OAuth 설정 확인
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        st.warning("""
        ### ⚙️ Google OAuth 설정 필요
        
        `.streamlit/secrets.toml` 파일에 다음 내용을 추가하세요:
        
        ```toml
        GOOGLE_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
        GOOGLE_CLIENT_SECRET = "your-client-secret"
        REDIRECT_URI = "http://localhost:8501"
        ```
        
        또는 환경 변수로 설정하세요.
        
        **OAuth 클라이언트 생성 방법:**
        1. [Google Cloud Console](https://console.cloud.google.com/)에서 프로젝트 생성
        2. Google Drive API 활성화
        3. OAuth 동의 화면 구성
        4. 사용자 인증 정보 > OAuth 2.0 클라이언트 ID 생성 (웹 애플리케이션)
        5. 승인된 리디렉션 URI에 `http://localhost:8501` 추가
        """)
        return
    
    # 세션 상태 초기화
    if 'google_credentials' not in st.session_state:
        st.session_state.google_credentials = None
    if 'google_user' not in st.session_state:
        st.session_state.google_user = None
    
    # URL 파라미터에서 인증 코드 확인
    query_params = st.query_params
    
    if 'code' in query_params and st.session_state.google_credentials is None:
        try:
            code = query_params['code']
            state = query_params.get('state', '')
            credentials = exchange_code_for_credentials(code, state)
            st.session_state.google_credentials = credentials
            
            # 사용자 정보 가져오기
            user_info = get_user_info(credentials)
            st.session_state.google_user = user_info
            
            # URL 파라미터 제거
            st.query_params.clear()
            st.rerun()
        except Exception as e:
            st.error(f"인증 오류: {str(e)}")
            st.query_params.clear()
    
    # 사이드바 - 로그인 상태
    st.sidebar.markdown(f"### {icon('lock-key')} Google 계정", unsafe_allow_html=True)
    
    if st.session_state.google_credentials and st.session_state.google_user:
        user = st.session_state.google_user
        st.sidebar.success(f"{user.get('email', '연결됨')}")
        
        if st.sidebar.button("로그아웃", icon=":material/logout:"):
            st.session_state.google_credentials = None
            st.session_state.google_user = None
            st.rerun()
        
        # Drive 파일 표시
        try:
            service = get_drive_service(st.session_state.google_credentials)
            
            # 폴더 이름 입력
            folder_name = st.sidebar.text_input(
                "폴더 이름",
                value="perplexity_results",
                help="Google Drive의 MyDrive 내 폴더 이름"
            )
            
            # 폴더 ID 찾기
            folder_id = None
            if folder_name:
                with st.spinner(f"'{folder_name}' 폴더 검색 중..."):
                    folder_id = find_folder_by_name(service, folder_name)
                
                if not folder_id:
                    st.warning(f"'{folder_name}' 폴더를 찾을 수 없습니다.")
                    return
            
            with st.spinner("파일 목록 로딩 중..."):
                files = list_csv_files(service, folder_id)
            
            if not files:
                st.info("CSV 파일이 없습니다.")
                return
            
            groups = group_files_by_source(files)
            
            if not groups:
                st.warning("패턴에 맞는 CSV 파일이 없습니다.")
                return
            
            st.sidebar.markdown(f"### {icon('file-text')} 파일 목록", unsafe_allow_html=True)
            selected_source = st.sidebar.selectbox(
                "분석 결과 선택",
                options=list(groups.keys()),
                format_func=lambda x: f"{groups[x].get('source', x)} (토큰: {groups[x].get('tokens', 'N/A')})"
            )
            
            if selected_source:
                group = groups[selected_source]
                
                st.markdown(f"## {icon('chart-bar', 'lg')} {group.get('source', selected_source)}", unsafe_allow_html=True)
                st.caption(f"목표 토큰 수: {group.get('tokens', 'N/A')}")
                
                tab1, tab2 = st.tabs(["문단 (Paragraph)", "문장 (Sentence)"])
                
                with tab1:
                    if group['paragraph']:
                        with st.spinner("문단 데이터 로딩 중..."):
                            df_para = download_file_as_dataframe(service, group['paragraph']['id'])
                        display_dataframe_with_features(df_para, f"{selected_source}_para")
                    else:
                        st.info("문단 데이터가 없습니다.")
                
                with tab2:
                    if group['sentence']:
                        with st.spinner("문장 데이터 로딩 중..."):
                            df_sent = download_file_as_dataframe(service, group['sentence']['id'])
                        display_dataframe_with_features(df_sent, f"{selected_source}_sent")
                    else:
                        st.info("문장 데이터가 없습니다.")
        
        except Exception as e:
            st.error(f"Google Drive 접근 오류: {str(e)}")
            if st.button("다시 로그인"):
                st.session_state.google_credentials = None
                st.session_state.google_user = None
                st.rerun()
    
    else:
        # 로그인 버튼
        st.markdown(f"### {icon('lock-key')} Google 계정으로 로그인", unsafe_allow_html=True)
        st.info("Google Drive의 CSV 파일을 조회하려면 로그인하세요.")
        
        try:
            auth_url, state, _ = get_google_auth_url()
            st.link_button("Google 로그인", auth_url, type="primary", icon=":material/key:")
        except Exception as e:
            st.error(f"OAuth URL 생성 오류: {str(e)}")


def main():
    st.markdown(f"# {icon('chart-bar', 'lg')} Perplexity 분석 결과 뷰어", unsafe_allow_html=True)
    st.caption("CSV 파일 조회, 검색, 정렬, 필터링, 다운로드")
    
    # 모드 선택
    st.sidebar.markdown(f"## {icon('gear')} 설정", unsafe_allow_html=True)
    mode = st.sidebar.radio(
        "데이터 소스",
        ["로컬 파일", "Google Drive"],
        index=1,
        captions=["로컬 폴더에서 CSV 로드", "Google Drive에서 CSV 로드"]
    )
    
    st.sidebar.divider()
    
    if mode == "로컬 파일":
        local_mode()
    else:
        google_drive_mode()


if __name__ == "__main__":
    main()
