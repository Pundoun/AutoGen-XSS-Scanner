import asyncio
import sys
import streamlit as st
import autogen
from dotenv import load_dotenv
import os
import json
import urllib.parse
import re
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from bs4 import BeautifulSoup
import traceback
from datetime import datetime
import sqlite3

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    print("INFO: Applied WindowsProactorEventLoopPolicy.")
else:
    print("INFO: Using default event loop policy.")
load_dotenv()
USER_PROVIDED_DATETIME_UTC = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
USER_PROVIDED_LOGIN = os.getenv("USER_LOGIN_NAME", "Lê Khoa & Như Quỳnh") 
TARGET_DEEPSEEK_MODEL = os.getenv("AUTOGEN_MODEL_NAME", "deepseek-coder")

for key in ['text_report_content', 'playwright_global_instance', 'playwright_browser', 
            'playwright_context_active', 'conversation_log_output', 'last_report_data_for_db',
            'max_urls_to_crawl', 'max_crawl_depth', 'max_tool_calls']:
    if key not in st.session_state:
        st.session_state[key] = None

DB_FILE = "xss_scan_reports.db"

USER_PROXY_AGENT_NAME = "User_Proxy_App" 
WEB_INTERACTION_AGENT_NAME = "Web_Execution_Bot"
COORDINATOR_AGENT_NAME = "XSS_Scan_Orchestrator"
PAYLOAD_GENERATOR_AGENT_NAME = "XSS_Payload_Forge"
MAX_PAYLOADS_PER_POINT = 5 

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT NOT NULL, scan_datetime_utc TEXT NOT NULL,
        user_login TEXT, llm_model TEXT, vulnerability_found BOOLEAN DEFAULT FALSE,
        vulnerabilities_details TEXT, full_report_text TEXT, known_injection_point TEXT,
        crawled_urls_count INTEGER DEFAULT 0
    )""")
    conn.commit(); conn.close()
    print("INFO: Database initialized successfully.")

def save_report_to_db(report_data):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        report_data.setdefault('crawled_urls_count', 0)
        cursor.execute("""INSERT INTO reports (target_url, scan_datetime_utc, user_login, llm_model, 
                             vulnerability_found, vulnerabilities_details, full_report_text, 
                             known_injection_point, crawled_urls_count)
                           VALUES (:target_url, :scan_datetime_utc, :user_login, :llm_model, 
                                   :vulnerability_found, :vulnerabilities_details, :full_report_text, 
                                   :known_injection_point, :crawled_urls_count)""", report_data)
        conn.commit()
        if hasattr(st, 'sidebar') and st.sidebar: st.sidebar.success(f"Báo cáo cho {report_data.get('target_url','N/A')} đã lưu.")
        print(f"INFO: Report saved for {report_data.get('target_url','N/A')}")
    except sqlite3.Error as e:
        log_error(f"Lỗi SQLite: {e}", exec_info=False)
        if hasattr(st, 'sidebar') and st.sidebar: st.sidebar.error("Lỗi lưu DB.")
    finally: conn.close()

def log_error(message: str, exec_info=True):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"); full_msg = f"[{ts}] ERROR: {message}"
    if exec_info: full_msg += f"\n{traceback.format_exc()}"
    if hasattr(st, 'error'): st.error(message)
    print(full_msg); 
    try:
        with open("autogen_app_error.log", "a", encoding="utf-8") as f: f.write(full_msg + "\n\n")
    except Exception as e_log: print(f"CRITICAL: Could not write to error log file: {e_log}")

def init_playwright_if_needed():
    if not st.session_state.get('playwright_browser') or not st.session_state.playwright_browser.is_connected():
        print("DEBUG: Init Playwright...")
        try:
            close_playwright_resources(called_from_init=True) 
            st.session_state.playwright_global_instance = sync_playwright()
            pw_cm = st.session_state.playwright_global_instance.__enter__()
            st.session_state.playwright_browser = pw_cm.chromium.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'])
            print("DEBUG: Playwright initialized."); return True
        except Exception as e:
            log_error(f"Playwright init error: {e}"); 
            for key_pw in ['playwright_global_instance', 'playwright_browser', 'playwright_context_active']: st.session_state[key_pw] = None
            return False
    return True

def get_playwright_page():
    if not init_playwright_if_needed(): log_error("Playwright not initialized.", exec_info=False); return None
    try:
        if not st.session_state.get('playwright_context_active'):
            st.session_state.playwright_context_active = st.session_state.playwright_browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                java_script_enabled=True, ignore_https_errors=True )
            print("DEBUG: New Playwright context created.")
        if st.session_state.playwright_context_active:
            page = st.session_state.playwright_context_active.new_page(); print("DEBUG: New Playwright page obtained."); return page
        else: log_error("Playwright context is None after creation.", exec_info=False); return None
    except Exception as e:
        log_error(f"Get page error: {e}")
        if st.session_state.get('playwright_context_active'):
            try: st.session_state.playwright_context_active.close(); print("DEBUG: Closed problematic context.")
            except Exception as e_close_ctx: print(f"DEBUG: Error closing context: {e_close_ctx}")
        st.session_state.playwright_context_active = None; return None

def close_playwright_resources(called_from_init=False):
    if not called_from_init: print("DEBUG: Closing Playwright...")
    closed = False; sidebar_available = hasattr(st, 'sidebar') and st.sidebar is not None
    try:
        if st.session_state.get('playwright_context_active'): st.session_state.playwright_context_active.close(); closed = True
        if st.session_state.get('playwright_browser') and st.session_state.playwright_browser.is_connected(): st.session_state.playwright_browser.close(); closed = True
        if st.session_state.get('playwright_global_instance'): st.session_state.playwright_global_instance.__exit__(None,None,None); closed = True
        for key_pw in ['playwright_global_instance', 'playwright_browser', 'playwright_context_active']: st.session_state[key_pw] = None
        if sidebar_available:
            if closed and not called_from_init: st.sidebar.info("Playwright resources closed.")
            elif not called_from_init: st.sidebar.info("No active Playwright resources or already closed.")
    except Exception as e:
        if not called_from_init: log_error(f"Playwright cleanup error: {e}")

def tool_fetch_web_content_with_playwright(url: str) -> str:
    page = get_playwright_page(); 
    if not page: return json.dumps({"error": "Không thể khởi tạo trang Playwright."})
    s_url = urllib.parse.urlsplit(url).geturl()
    if not (s_url.startswith("http://") or s_url.startswith("https://")): return json.dumps({"error": f"URL không hợp lệ: '{url}'"})
    st.write(f"Tool (Fetch): Đang tải nội dung từ {s_url}...")
    content = None; cur_url = s_url; error_msg = None
    try:
        page.goto(s_url, timeout=45000, wait_until="networkidle"); content = page.content(); cur_url = page.url
    except Exception as e: error_msg = str(e); log_error(f"Lỗi tải URL {s_url}: {type(e).__name__} - {e}", exec_info=False)
    finally:
        if page and not page.is_closed(): page.close()
    if error_msg: return json.dumps({"error": error_msg, "url": s_url})
    return json.dumps({"html_content": content, "url": cur_url})

def tool_extract_links_from_html(html_content: str, base_url: str) -> str:
    if not html_content: return json.dumps({"error": "Nội dung HTML trống."})
    st.write(f"Tool (Extract Links): Trích xuất link từ HTML (base: {base_url})...")
    try:
        soup = BeautifulSoup(html_content, 'html.parser'); extracted_links = set()
        parsed_base_url = urllib.parse.urlparse(base_url); base_domain = parsed_base_url.netloc
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')): continue
            absolute_link = urllib.parse.urljoin(base_url, href)
            parsed_link = urllib.parse.urlparse(absolute_link)
            if parsed_link.netloc == base_domain: extracted_links.add(urllib.parse.urlunparse(parsed_link._replace(fragment="")))
        st.write(f"Tool (Extract Links): Tìm thấy {len(extracted_links)} link nội bộ duy nhất.")
        return json.dumps({"extracted_links": list(extracted_links)})
    except Exception as e: log_error(f"Lỗi trích xuất link: {e}", exec_info=False); return json.dumps({"error": str(e)})

def tool_find_potential_injection_points_with_bs4(html_content: str, base_url: str) -> str:
    if not html_content: return json.dumps({"error": "Nội dung HTML trống."})
    st.write(f"Tool (Find Points): Phân tích HTML từ {base_url}...")
    try:
        soup = BeautifulSoup(html_content, 'html.parser'); points = []
        search_keywords = ["search", "query", "keyword", "q", "s", "tìm", "Tim", " ಹುಡುಕಿ"]
        submit_texts_regex = r'Submit|Send|Search|Go|OK|Save|Login|Tìm kiếm|Đăng nhập|Gửi|ค้นหา|ค้น'
        for form_idx, form in enumerate(soup.find_all('form', limit=20)):
            action = form.get('action'); full_action = urllib.parse.urljoin(base_url, action) if action else base_url
            form_id_attr = form.get('id'); form_unique_id = form_id_attr if form_id_attr else f"autogen_form_{form_idx}"
            form_is_search_form = (form_id_attr and any(kw in form_id_attr.lower() for kw in search_keywords)) or \
                                  (action and any(kw in action.lower() for kw in search_keywords))
            details = {"type": "form", "id": form_unique_id, "action": full_action, "method": form.get('method', 'GET').upper(), "inputs": [], "is_search_form": form_is_search_form, "submit_button_selector": None}
            submit_sel = None
            for cand_s_type in ['button[type="submit"]', 'input[type="submit"]', 'button']: 
                for cand_s in form.select(cand_s_type):
                    if cand_s.get('id'): submit_sel = f"#{cand_s['id']}"; break
                    if cand_s.get('name'): submit_sel = f"{cand_s.name}[name='{cand_s['name']}']"; break
                    button_text = (cand_s.get_text(strip=True) or cand_s.get('value','')).lower()
                    if re.search(submit_texts_regex, button_text, re.IGNORECASE):
                        submit_sel = f"form#{form_unique_id} {cand_s.name}:contains('{cand_s.get_text(strip=True)}')" if form_id_attr and cand_s.name == 'button' else f"{cand_s.name}[type='{cand_s.get('type','button')}']"
                        break
                if submit_sel: break
            details["submit_button_selector"] = submit_sel
            for inp_idx, inp in enumerate(form.find_all(['input', 'textarea', 'select'], limit=30)):
                inp_id = inp.get('id'); inp_name = inp.get('name'); sel = None; inp_type = inp.get('type', inp.name)
                if inp_id: sel = f"#{inp_id}"
                elif inp_name: sel = f"form#{form_unique_id} [name='{inp_name}']" if form_id_attr else f"[name='{inp_name}']"
                elif inp_type and form_id_attr : sel = f"form#{form_unique_id} [type='{inp_type}']" 
                elif form_id_attr: sel = f"form#{form_unique_id} {inp.name}:nth-of-type({inp_idx+1})"
                is_sf = any(kw in (inp_name or "").lower() for kw in search_keywords) or any(kw in (inp_id or "").lower() for kw in search_keywords) or any(kw in (inp.get('placeholder','') or "").lower() for kw in search_keywords) or inp_type == "search" or (form_is_search_form and inp_type in ["text", "search"])
                details["inputs"].append({"id": inp_id or f"{form_unique_id}_inp_{inp_idx}", "tag": inp.name, "type": inp_type, "name": inp_name or "", "selector": sel, "is_search_field": is_sf, "value": inp.get("value", "")})
            points.append(details)
        for inp_idx, inp in enumerate(soup.find_all(['input', 'textarea'], limit=30)): 
            if not inp.find_parent('form'):
                inp_id = inp.get('id'); inp_name = inp.get('name'); sel = None; inp_type = inp.get('type', inp.name)
                if inp_id: sel = f"#{inp_id}"
                elif inp_name: sel = f"[name='{inp_name}']"
                is_sf = any(kw in (inp_name or "").lower() for kw in search_keywords) or any(kw in (inp_id or "").lower() for kw in search_keywords) or any(kw in (inp.get('placeholder','') or "").lower() for kw in search_keywords) or inp_type == "search"
                points.append({"type": "standalone_input", "id": inp_id or f"sa_inp_{inp_idx}", "tag": inp.name, "type": inp_type, "name": inp_name or "", "selector": sel, "is_search_field": is_sf, "value": inp.get("value", ""),"submit_button_selector": None })
        return json.dumps({"injection_points": points, "base_url_analyzed": base_url})
    except Exception as e: log_error(f"Parse HTML error: {e}", exec_info=False); return json.dumps({"error": str(e)})

def tool_test_xss_payload_in_url_with_playwright(
    target_url_with_payload: str, 
    payload_description: str, 
    event_to_trigger: str = None, 
    element_to_target_selector: str = None,
    param_name_if_standalone: str = None, 
    base_url_for_description: str = None 
) -> str:
    page = get_playwright_page(); 
    if not page: return json.dumps({"error": "Không thể khởi tạo trang cho URL test."})
    
    final_payload_desc = payload_description
    if param_name_if_standalone and base_url_for_description:
        final_payload_desc = f"Thử nghiệm standalone input (tham số: '{param_name_if_standalone}') trên {base_url_for_description} bằng cách chèn vào URL."
    elif base_url_for_description: 
        final_payload_desc = f"{payload_description} trên {base_url_for_description}."

    res = {"alert_detected": False, "alert_message": None, "error": None, "final_url": None, 
           "payload_tested_description": final_payload_desc, 
           "event_triggered": event_to_trigger, "target_selector_used": element_to_target_selector,
           "param_name_tested_if_standalone": param_name_if_standalone}
    alert_flag = [False]; alert_txt = [None]    
    
    def h_dialog(d): 
        alert_flag[0]=True; alert_txt[0]=d.message; 
        st.success(f"Tool(URL): ALERT! {d.message} ({final_payload_desc})")
        try: d.accept()
        except Exception as e_ad: print(f"DEBUG: Dialog accept error: {e_ad}")
    
    page.once("dialog", h_dialog); st.write(f"Tool(URL): Testing '{final_payload_desc}'..."); st.caption(f"URL: {target_url_with_payload[:100]}...")
    try:
        page.goto(target_url_with_payload, timeout=25000, wait_until="domcontentloaded"); page.wait_for_timeout(1500); res["final_url"] = page.url
        if event_to_trigger and element_to_target_selector:
            st.write(f"Tool: Kích hoạt '{event_to_trigger}' trên '{element_to_target_selector}'...")
            for el_idx, el in enumerate(page.locator(element_to_target_selector).all()):
                if alert_flag[0]: break
                try:
                    if event_to_trigger == "hover": el.hover(timeout=1500)
                    elif event_to_trigger == "click": el.click(timeout=1500)
                    elif event_to_trigger == "focus": el.focus(timeout=1500)
                    st.write(f"Tool: Đã kích hoạt '{event_to_trigger}' trên element {el_idx+1}."); page.wait_for_timeout(700);
                    if alert_flag[0]: break
                except Exception as e_trig: st.warning(f"Tool: Kích hoạt thất bại trên el {el_idx+1}: {e_trig}")
        if not alert_flag[0]: page.wait_for_timeout(3000) 
    except Exception as e: 
        res["error"] = str(e); log_error(f"Lỗi URL Test: {type(e).__name__}", exec_info=False)
        if page and not page.is_closed():
            try: res["final_url"]=page.url 
            except: res["final_url"]=target_url_with_payload
        else: res["final_url"]=target_url_with_payload
    finally: 
        if page and not page.is_closed(): page.close()
    res["alert_detected"] = alert_flag[0]; res["alert_message"] = alert_txt[0]; return json.dumps(res)

def tool_submit_form_and_test_event(target_page_url: str, form_submit_details: dict, payload_description: str, event_to_trigger_after_submit: str = None, element_to_target_after_submit_selector: str = None) -> str:
    page = get_playwright_page(); 
    if not page: return json.dumps({"error": "Không thể khởi tạo trang cho form test."})
    res = {"alert_detected": False, "alert_message": None, "error": None, "final_url_after_submit": target_page_url, "payload_tested_description": payload_description, "form_details_used": form_submit_details, "event_triggered_after_submit": event_to_trigger_after_submit, "target_selector_after_submit_used": element_to_target_after_submit_selector}
    alert_flag = [False]; alert_txt = [None]
    def h_dialog_form(d): 
        alert_flag[0]=True; alert_txt[0]=d.message; 
        st.success(f"Tool(Form): ALERT! {d.message} ({payload_description})")
        try: d.accept()
        except Exception as e_ad: print(f"DEBUG: Dialog accept error (form): {e_ad}")
    page.once("dialog", h_dialog_form); st.write(f"Tool(Form): Submit '{payload_description}'..."); st.json(form_submit_details)
    try:
        page.goto(target_page_url, timeout=30000, wait_until="networkidle")
        inputs_to_fill = form_submit_details.get("inputs_to_fill", [])
        if not inputs_to_fill: raise ValueError("Không có inputs_to_fill.")
        for inp_det in inputs_to_fill:
            inp_sel, p_val = inp_det.get("selector"), inp_det.get("payload")
            if not inp_sel or p_val is None: st.warning(f"Tool: Bỏ qua input: {inp_det}"); continue
            st.write(f"Tool: Điền '{inp_sel}' với '{str(p_val)[:50]}...'")
            page.locator(inp_sel).fill(str(p_val)); page.wait_for_timeout(200)
        submit_sel = form_submit_details.get("submit_button_selector")
        if not submit_sel:
            last_inp_sel = inputs_to_fill[-1].get("selector")
            if last_inp_sel: st.write(f"Tool: Không có submit selector. Nhấn Enter trên '{last_inp_sel}'."); page.locator(last_inp_sel).press("Enter")
            else: raise ValueError("Không có submit selector và không có input cuối để nhấn Enter.")
        else: st.write(f"Tool: Click submit '{submit_sel}'."); page.locator(submit_sel).click()
        st.write("Tool: Form đã submit. Chờ cập nhật..."); 
        try: page.wait_for_load_state("networkidle", timeout=25000)
        except PlaywrightTimeoutError: st.warning("Tool: Timeout networkidle sau submit. Tiếp tục.")
        res["final_url_after_submit"]=page.url; st.write(f"Tool: URL sau submit: {page.url}"); page.wait_for_timeout(1500)
        if event_to_trigger_after_submit and element_to_target_after_submit_selector:
            st.write(f"Tool: Kích hoạt '{event_to_trigger_after_submit}' trên '{element_to_target_after_submit_selector}' sau submit...")
            for el_idx, el in enumerate(page.locator(element_to_target_after_submit_selector).all()):
                if alert_flag[0]: break
                try:
                    if event_to_trigger_after_submit == "hover": el.hover(timeout=1500)
                    elif event_to_trigger_after_submit == "click": el.click(timeout=1500)
                    elif event_to_trigger_after_submit == "focus": el.focus(timeout=1500)
                    st.write(f"Tool: Đã kích hoạt '{event_to_trigger_after_submit}' trên element {el_idx+1} (sau submit)."); page.wait_for_timeout(700);
                    if alert_flag[0]: break
                except Exception as e_trig_ps: st.warning(f"Tool: Kích hoạt sau submit thất bại trên el {el_idx+1}: {e_trig_ps}")
        if not alert_flag[0]: page.wait_for_timeout(3000)
    except Exception as e: 
        res["error"] = str(e); log_error(f"Lỗi Form Test: {type(e).__name__}", exec_info=False); 
        if page and not page.is_closed():
            try: res["final_url_after_submit"] = page.url
            except: res["final_url_after_submit"] = target_page_url
        else: res["final_url_after_submit"] = target_page_url
    finally: 
        if page and not page.is_closed(): page.close()
    res["alert_detected"] = alert_flag[0]; res["alert_message"] = alert_txt[0]; return json.dumps(res)

def load_llm_config():
    config_path = "agents_config.json"; actual_api_key = os.getenv("DEEPSEEK_API_KEY")
    if not actual_api_key: log_error("CRITICAL: DEEPSEEK_API_KEY not in .env.", exec_info=False); return None
    if not os.path.exists(config_path): log_error(f"CRITICAL: '{config_path}' not found.", exec_info=False); return None
    try:
        with open(config_path, 'r', encoding='utf-8') as f: cfg_list_file = json.load(f)
        if not isinstance(cfg_list_file, list): log_error(f"Error: '{config_path}' not list.", exec_info=False); return None
        proc_cfg_list = []; model_found = False
        for item in cfg_list_file:
            if not isinstance(item, dict): continue
            new_cfg = item.copy()
            if new_cfg.get("model") == TARGET_DEEPSEEK_MODEL:
                if new_cfg.get("api_key") == "env": new_cfg["api_key"] = actual_api_key
                proc_cfg_list.append(new_cfg); model_found = True; break 
        if not model_found: log_error(f"No config for '{TARGET_DEEPSEEK_MODEL}'.", exec_info=False); return None
        if not proc_cfg_list: log_error(f"Processed config for '{TARGET_DEEPSEEK_MODEL}' empty.", exec_info=False); return None
    except Exception as e: log_error(f"LLM config error: {e}"); return None
    final_cfg = {"config_list": proc_cfg_list, "cache_seed": None, "timeout": 600, "temperature": 0.0}
    print(f"DEBUG: Loaded LLM Config: {json.dumps(final_cfg, indent=2)}"); return final_cfg

# --- MAIN AUTOGEN ORCHESTRATION FUNCTION ---
def run_xss_analysis_and_discovery_with_autogen(target_url: str, known_injection_point_info: str, llm_config_dict: dict):
    st.session_state.text_report_content = None; st.session_state.last_report_data_for_db = None 
    if not llm_config_dict or not llm_config_dict.get("config_list"):
        log_error("Critical: Invalid LLM config.", exec_info=False); return [{"name": "SysErr_LLM", "content": "LLM cfg err."}]
    if not init_playwright_if_needed(): return [{"name": "SysErr_PW", "content": "PW init err."}]

    TERMINATION_PHRASE_TEXT = "HOÀN TẤT TOÀN BỘ QUY TRÌNH PHÂN TÍCH, THỬ NGHIỆM VÀ BÁO CÁO XSS."
    TERMINATION_REGEX = re.compile(r"\b" + re.escape(TERMINATION_PHRASE_TEXT) + r"\b", re.IGNORECASE)
    
    MAX_URLS_TO_CRAWL = st.session_state.get("max_urls_to_crawl", 5) 
    MAX_CRAWL_DEPTH = st.session_state.get("max_crawl_depth", 1)   
    MAX_TOTAL_TOOL_CALLS_OVERALL = st.session_state.get("max_tool_calls", 75)

    try:
        user_proxy = autogen.UserProxyAgent(
            name=USER_PROXY_AGENT_NAME, human_input_mode="NEVER", max_consecutive_auto_reply=3,
            is_termination_msg=lambda x: TERMINATION_REGEX.search(x.get("content", "").strip()) is not None or \
                                         x.get("content", "").strip().upper() == "TERMINATE_GROUPCHAT",
            code_execution_config=False, description="User rep, initiates & receives final report."
        )
        agent_llm_config = llm_config_dict.copy()
        injection_info_prompt = f"Known injection point for initial URL: '{known_injection_point_info}'." if known_injection_point_info else "No specific injection point known for initial URL."
        
        web_interaction_specialist = autogen.AssistantAgent(
            name=WEB_INTERACTION_AGENT_NAME, llm_config=agent_llm_config,
            system_message=f"""Bạn là trợ lý web. PHẢI trả lời bằng tiếng Việt.
    Tools (gọi bằng function call):
    - `tool_fetch_web_content_with_playwright(url: str)`
    - `tool_extract_links_from_html(html_content: str, base_url: str)`
    - `tool_find_potential_injection_points_with_bs4(html_content: str, base_url: str)`
    - `tool_test_xss_payload_in_url_with_playwright(target_url_with_payload: str, payload_description: str, event_to_trigger: str = None, element_to_target_selector: str = None, param_name_if_standalone: str = None, base_url_for_description: str = None)`
    - `tool_submit_form_and_test_event(...)`
    Sau khi tool chạy, tóm tắt kết quả bằng tiếng Việt.""",
            function_map={
                "tool_fetch_web_content_with_playwright": tool_fetch_web_content_with_playwright,
                "tool_extract_links_from_html": tool_extract_links_from_html,
                "tool_find_potential_injection_points_with_bs4": tool_find_potential_injection_points_with_bs4,
                "tool_test_xss_payload_in_url_with_playwright": tool_test_xss_payload_in_url_with_playwright,
                "tool_submit_form_and_test_event": tool_submit_form_and_test_event,
            }, description="Thực thi tác vụ web qua tool."
        )
        
        xss_analysis_coordinator = autogen.AssistantAgent(
            name=COORDINATOR_AGENT_NAME, llm_config=agent_llm_config,
            system_message=f"""Bạn là điều phối viên phân tích XSS tự động. PHẢI trả lời bằng tiếng Việt.
    Mục tiêu: Tìm XSS cho URL ban đầu: `{target_url}` và các trang liên quan. {injection_info_prompt}
    Giới hạn: Crawl tối đa {MAX_URLS_TO_CRAWL} URLs, độ sâu {MAX_CRAWL_DEPTH}. Thử {MAX_PAYLOADS_PER_POINT} payloads/điểm chèn. Tổng tool call tối đa: {MAX_TOTAL_TOOL_CALLS_OVERALL}.
    
    QUY TRÌNH:
    PHẦN 1: THU THẬP URL (CRAWLING)
    1.  KHỞI TẠO: `urls_to_visit_q = [('{target_url}', 0)]`; `all_discovered_urls = set(['{target_url}'])`; `final_urls_for_analysis = []`; `tool_calls_count = 0`.
    2.  NẾU (`MAX_URLS_TO_CRAWL` > 1 VÀ `MAX_CRAWL_DEPTH` >= 0):
        LẶP (khi `urls_to_visit_q` không rỗng VÀ `len(all_discovered_urls)` < `MAX_URLS_TO_CRAWL` VÀ `tool_calls_count` < (`MAX_TOTAL_TOOL_CALLS_OVERALL` * 0.3) ):
        a.  Lấy `(crawl_url, depth)` từ `urls_to_visit_q`. `tool_calls_count` += 1.
        b.  Gọi `tool_fetch_web_content_with_playwright(crawl_url)`.
        c.  Nếu có HTML và `depth` < `MAX_CRAWL_DEPTH`: `tool_calls_count` += 1. Gọi `tool_extract_links_from_html(html, crawl_url)`. Với mỗi `new_link`, nếu chưa trong `all_discovered_urls` và `len(all_discovered_urls)` < `MAX_URLS_TO_CRAWL`, thêm vào `all_discovered_urls` và `urls_to_visit_q` với `depth+1`.
    3.  `final_urls_for_analysis = list(all_discovered_urls)`. Thông báo số URL sẽ phân tích.

    PHẦN 2: PHÂN TÍCH VÀ THỬ PAYLOAD TRÊN `final_urls_for_analysis`
    4.  `processed_urls_for_payload_testing = set()`.
    5.  LẶP QUA TỪNG `url_to_analyze` TRONG `final_urls_for_analysis` (nếu `tool_calls_count` < `MAX_TOTAL_TOOL_CALLS_OVERALL`):
        a.  Nếu `url_to_analyze` trong `processed_urls_for_payload_testing`, bỏ qua. Thêm vào `processed_urls_for_payload_testing`. 
        b.  THU THẬP ĐIỂM CHÈN: `tool_calls_count` += 1. Gọi `tool_fetch_web_content_with_playwright(url_to_analyze)`. Nếu có HTML, `tool_calls_count` += 1; gọi `tool_find_potential_injection_points_with_bs4(html, url_to_analyze)`. Kết quả là `injection_points_data`.
        c.  LẶP QUA TỪNG `point` TRONG `injection_points_data.get('injection_points', [])` (nếu có):
            i.  `tool_calls_count` += 1. Yêu cầu '{PAYLOAD_GENERATOR_AGENT_NAME}' tạo BỘ {MAX_PAYLOADS_PER_POINT} PAYLOADS XSS THÔ đa dạng cho `point`. Gợi ý payload `<a onmouseover="alert('XSS_OM_{USER_PROVIDED_LOGIN}')">OM_TEXT_TARGET</a>` nếu `point.get('is_search_field', False)` hoặc `point.get('is_search_form', False)` là true.
            ii. LẶP QUA {MAX_PAYLOADS_PER_POINT} PAYLOADS (`current_payload`):
                - Nếu `tool_calls_count` >= `MAX_TOTAL_TOOL_CALLS_OVERALL`, dừng sớm và chuyển sang báo cáo.
                - `tool_calls_count` += 1.
                - THỬ NGHIỆM:
                    *   Nếu `point['type'] == 'form'`:
                        - `target_page_for_form = point.get('action', url_to_analyze)` 
                        - `form_details = {{"inputs_to_fill": [], "submit_button_selector": point.get('submit_button_selector')}}`.
                        - `main_input_to_test = None`
                        - `for inp_detail in point.get('inputs', []): if inp_detail.get('is_search_field'): main_input_to_test = inp_detail; break`
                        - `if not main_input_to_test and point.get('inputs'): main_input_to_test = next((inp for inp in point['inputs'] if inp.get('type') in ['text', 'search']), point['inputs'][0] if point['inputs'] else None)`
                        - `if main_input_to_test and main_input_to_test.get('selector'): form_details["inputs_to_fill"].append({{"selector": main_input_to_test.get('selector'), "payload": current_payload}})`
                        - `else: continue`
                        - `event_trigger = None`; `element_selector_after_submit = None`. Nếu `current_payload` chứa "onmouseover" và "OM_TEXT_TARGET": `event_trigger="hover"`; `element_selector_after_submit="a:has-text('OM_TEXT_TARGET'),div:has-text('OM_TEXT_TARGET')"`.
                        - Gọi `tool_submit_form_and_test_event(target_page_for_form, form_details, "Thử nghiệm XSS qua Form", event_trigger, element_selector_after_submit)`.
                    *   Nếu `point['type'] == 'standalone_input'` VÀ `point.get('selector')`:
                        `input_name_for_url_param = point.get('name')`
                        `if input_name_for_url_param:` 
                           `encoded_payload = urllib.parse.quote_plus(current_payload)`
                           `parsed_original_url = urllib.parse.urlparse(url_to_analyze)`
                           `original_query_params = urllib.parse.parse_qs(parsed_original_url.query)`
                           `original_query_params[input_name_for_url_param] = [encoded_payload]`
                           `new_query_string = urllib.parse.urlencode(original_query_params, doseq=True)`
                           `test_url = urllib.parse.urlunparse(parsed_original_url._replace(query=new_query_string))`
                           `event_trigger = None`; `element_selector = None`
                           `payload_description_for_tool = "Thử nghiệm XSS trên standalone input qua URL parameter."` 
                           Nếu `current_payload` chứa "onmouseover" và "OM_TEXT_TARGET": 
                             `event_trigger="hover"`
                             `element_selector="a:has-text('OM_TEXT_TARGET'),div:has-text('OM_TEXT_TARGET')"`
                           Gọi `tool_test_xss_payload_in_url_with_playwright(test_url, payload_description_for_tool, event_trigger, element_selector, param_name_if_standalone=input_name_for_url_param, base_url_for_description=url_to_analyze)`.
                        `else:`
                           `# Không làm gì nếu standalone_input không có 'name', AI sẽ tự chuyển sang bước tiếp theo.`
                - PHÂN TÍCH: Nếu `alert_detected`, GHI NHẬN LỖ HỔNG (URL, payload, điểm chèn) và có thể dừng thử payload cho `point` này.
    6.  BÁO CÁO CUỐI CÙNG: Tổng hợp kết quả. Kết thúc bằng: {TERMINATION_PHRASE_TEXT}
    LƯU Ý: Nếu kẹt hoặc đạt `MAX_TOTAL_TOOL_CALLS_OVERALL`, tóm tắt và kết thúc. Nếu không làm gì được, gửi "TERMINATE_GROUPCHAT".
    """, description="Điều phối viên chính, crawling, phân tích sâu và kết thúc."
        )
        
        xss_payload_generator_agent = autogen.AssistantAgent(
            name=PAYLOAD_GENERATOR_AGENT_NAME, llm_config=agent_llm_config,
            system_message=f"""Bạn là chuyên gia tạo payload XSS. PHẢI trả lời bằng tiếng Việt.
    Nhiệm vụ:
    1.  Nhận yêu cầu từ '{COORDINATOR_AGENT_NAME}' tạo BỘ {MAX_PAYLOADS_PER_POINT} PAYLOADS.
    2.  Tạo BỘ {MAX_PAYLOADS_PER_POINT} PAYLOADS XSS THÔ đa dạng:
        -   `<script>alert('XSS_SCRIPT_{USER_PROVIDED_LOGIN}_'+Date.now())</script>`
        -   `<img src=x onerror="alert('XSS_IMG_{USER_PROVIDED_LOGIN}_'+Date.now())">`
        -   `<a onmouseover="alert('XSS_OM_{USER_PROVIDED_LOGIN}_'+Date.now())">OM_TEXT_TARGET</a>`
        -   `<input value='FOCUS_TEXT_TARGET' onfocus="alert('XSS_FOCUS_{USER_PROVIDED_LOGIN}_'+Date.now())">`
        -   `<details open ontoggle="alert('XSS_TOGGLE_{USER_PROVIDED_LOGIN}_'+Date.now())"><summary>ClickMe</summary>PayloadHere</details>` 
    3.  Định dạng: `{{"payloads_generated": ["<p1>",...,"<p{MAX_PAYLOADS_PER_POINT}>"], "notes": "Bộ {MAX_PAYLOADS_PER_POINT} payload, bao gồm event-based với text nhận diện OM_TEXT_TARGET/FOCUS_TEXT_TARGET."}}`
    Tóm tắt payload nếu được yêu cầu.""",
            description=f"Tạo bộ {MAX_PAYLOADS_PER_POINT} payload XSS đa dạng."
        )
        
        group_chat = autogen.GroupChat(agents=[user_proxy, web_interaction_specialist, xss_analysis_coordinator, xss_payload_generator_agent], messages=[], max_round=250, admin_name=COORDINATOR_AGENT_NAME)
        manager = autogen.GroupChatManager(groupchat=group_chat, llm_config=agent_llm_config)

    except Exception as e_agent_init: 
        log_error(f"Agent Init Error: {e_agent_init}", exec_info=True)
        return [{"name": "SysErr_AgentInit", "content": f"Agent init err.\nErr: {str(e_agent_init)}\n{traceback.format_exc()}"}]

    initial_message_to_coordinator = f"""Chào {COORDINATOR_AGENT_NAME}, bắt đầu phân tích XSS cho URL ban đầu: {target_url}. {injection_info_prompt} Crawl (Max URLs: {MAX_URLS_TO_CRAWL}, Max Depth: {MAX_CRAWL_DEPTH}, Max Tools: {MAX_TOTAL_TOOL_CALLS_OVERALL}), rồi phân tích và thử {MAX_PAYLOADS_PER_POINT} payload/điểm cho mỗi URL. Xử lý form/ô tìm kiếm cẩn thận, kích hoạt event cho payload onmouseover có text 'OM_TEXT_TARGET'."""
    
    st.info(f"🚀 Bắt đầu phiên làm việc của các Chuyên Gia AI cho URL: {target_url}")
    current_conversation_history = []
    
    try:
        user_proxy.initiate_chat(manager, message=initial_message_to_coordinator)
        current_conversation_history = group_chat.messages 
    except Exception as e_chat:
        log_error(f"Lỗi nghiêm trọng trong AutoGen chat: {e_chat}") 
        current_conversation_history.append({"name": "SysErr_Chat", "content": f"AutoGen Chat Err: {str(e_chat)}\n{traceback.format_exc()}"})
    
    final_report_content_header = f"# Báo Cáo Phân Tích XSS (có Crawling)\n## URL Ban Đầu: {target_url}\n";
    if known_injection_point_info: final_report_content_header += f"## Điểm Chèn Đã Biết (cho URL ban đầu): {known_injection_point_info}\n\n"
    else: final_report_content_header += "## Điểm Chèn Đã Biết: Không có\n\n"
    
    coordinator_final_report = None;
    if current_conversation_history: 
        for msg in reversed(current_conversation_history): 
            if msg.get("name") == COORDINATOR_AGENT_NAME and isinstance(msg.get("content"), str) and TERMINATION_REGEX.search(msg.get("content").strip()):
                coordinator_final_report = msg.get("content"); break 
    
    if coordinator_final_report:
        st.session_state.text_report_content = final_report_content_header + "## Báo Cáo Từ AI:\n" + coordinator_final_report
    elif current_conversation_history: 
        st.warning("Không tìm thấy báo cáo cuối cùng. Hiển thị toàn bộ nhật ký hội thoại.")
        formatted_log = "\n\n---\n\n".join([
            f"**{m.get('name', 'Unknown')}** ({m.get('role', 'assistant')}):\n"
            f"{json.dumps(m.get('content'), indent=2, ensure_ascii=False) if isinstance(m.get('content'), (dict, list)) else m.get('content', '')}"
            for m in current_conversation_history])
        st.session_state.text_report_content = final_report_content_header + "## Nhật Ký Hội Thoại Đầy Đủ:\n" + formatted_log
    else: st.session_state.text_report_content = final_report_content_header + "## Không có nhật ký hoặc báo cáo nào.\n"

    if st.session_state.text_report_content:
        found_vulns_details = []; vulnerability_actually_found = False
        if coordinator_final_report:
            report_lower = coordinator_final_report.lower()
            if "lỗ hổng xss đã xác nhận" in report_lower or "alert_detected: true" in report_lower or "vulnerability xss confirmed" in report_lower or "tìm thấy lỗ hổng xss" in report_lower:
                vulnerability_actually_found = True
                found_vulns_details.append({"summary": "XSS potentially confirmed by AI.", "details": "Review full report text."})
        
        crawled_urls_count = 0 
        st.session_state.last_report_data_for_db = {
            "target_url": target_url, "scan_datetime_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "user_login": USER_PROVIDED_LOGIN, "llm_model": TARGET_DEEPSEEK_MODEL,
            "vulnerability_found": vulnerability_actually_found,
            "vulnerabilities_details": json.dumps(found_vulns_details) if found_vulns_details else None,
            "full_report_text": st.session_state.text_report_content,
            "known_injection_point": known_injection_point_info,
            "crawled_urls_count": crawled_urls_count 
        }
    return current_conversation_history

st.set_page_config(page_title="Trợ Lý AI XSS Pro v12 (Final Fix) - LK&NQ", layout="wide")
init_db() 

col_title1, col_title2 = st.columns([3,1])
with col_title1:
    st.title("🎯 XSS DETECTION AND EXPLOITATION FRAMEWORK USING AUTOGEN MULTI-AGENT AI")
    st.caption(f"Model: {TARGET_DEEPSEEK_MODEL}. Phát triển bởi Lê Khoa & Như Quỳnh.")
with col_title2:
    st.markdown(f"Người dùng: **{USER_PROVIDED_LOGIN}**<br>Thời gian UTC: **{USER_PROVIDED_DATETIME_UTC}**", unsafe_allow_html=True)
st.markdown("---")

active_llm_config = load_llm_config() 
if not active_llm_config:
    st.error("CRITICAL: Lỗi tải LLM config. Kiểm tra `agents_config.json` và `.env`, rồi KHỞI ĐỘNG LẠI.")
    st.stop() 
else: st.success(f"LLM config cho '{TARGET_DEEPSEEK_MODEL}' đã tải.")

st.sidebar.header("Điều Khiển & Cài Đặt")
st.session_state.max_urls_to_crawl = st.sidebar.number_input("Số URL tối đa để crawl:", min_value=1, max_value=50, value=st.session_state.get("max_urls_to_crawl", 5), step=1)
st.session_state.max_crawl_depth = st.sidebar.number_input("Độ sâu crawling tối đa:", min_value=0, max_value=5, value=st.session_state.get("max_crawl_depth", 1), step=1, help="0 = chỉ URL gốc")
st.session_state.max_tool_calls = st.sidebar.number_input("Giới hạn tổng số Tool Call:", min_value=10, max_value=300, value=st.session_state.get("max_tool_calls", 75), step=5, help="Ngăn chặn chạy quá lâu/tốn kém.")


if st.sidebar.button("🧹 Dọn dẹp Playwright", key="cleanup_button_sidebar_main_v12"):
    close_playwright_resources()
st.sidebar.markdown("---")

main_target_url_input = st.text_input("Nhập URL chính để bắt đầu phân tích & crawling:", 
                                      value=st.session_state.get("main_target_url_input_val", ""),
                                      placeholder="Ví dụ: https://example.com") 
st.session_state.main_target_url_input_val = main_target_url_input
known_injection_param_input = st.text_input("Điểm chèn XSS đã biết (Tùy chọn, cho URL gốc, ví dụ: 'ô tìm kiếm'):", 
                                            value=st.session_state.get("known_injection_param_input_val", ""))
st.session_state.known_injection_param_input_val = known_injection_param_input

if st.button("🚀 Bắt đầu Phân Tích & Crawling", type="primary", key="start_analysis_button_main_v12"):
    st.session_state.text_report_content = None; st.session_state.conversation_log_output = [] 
    is_valid_url = main_target_url_input and (main_target_url_input.strip().startswith("http://") or main_target_url_input.strip().startswith("https://"))
    if not is_valid_url: st.warning("Vui lòng nhập URL hợp lệ.")
    elif not active_llm_config: st.error("Lỗi cấu hình LLM.")
    else:
        status_placeholder = st.empty()
        status_placeholder.info(f"🚀 AI ({TARGET_DEEPSEEK_MODEL}) đang chuẩn bị (Max URLs: {st.session_state.max_urls_to_crawl}, Max Depth: {st.session_state.max_crawl_depth}, Max Tools: {st.session_state.max_tool_calls})...")
        try:
            with st.spinner(f"🕵️‍♂️ AI đang làm việc (Crawling & Phân tích)..."):
                st.session_state.conversation_log_output = run_xss_analysis_and_discovery_with_autogen(
                    main_target_url_input.strip(), known_injection_param_input.strip(), active_llm_config)
            status_placeholder.success("✅ Phân tích, crawling và thử nghiệm hoàn tất!")
            if st.session_state.get('last_report_data_for_db'):
                save_report_to_db(st.session_state.last_report_data_for_db)
                st.session_state.last_report_data_for_db = None 
        except Exception as e: 
            log_error(f"Lỗi không mong muốn: {e}")
            status_placeholder.error(f"Lỗi nghiêm trọng. Kiểm tra 'autogen_app_error.log'. Lỗi: {e}")
            st.text_area("Traceback:", traceback.format_exc(), height=300)

st.markdown("---"); st.subheader("📜 Nhật Ký Tương Tác & Kết Quả AI:")
if st.session_state.conversation_log_output:
    for i, msg in enumerate(st.session_state.conversation_log_output):
        agent_name = msg.get('name', 'Unknown'); agent_role = msg.get('role', 'assistant') 
        icon_map = { 
            USER_PROXY_AGENT_NAME: "🧑‍💻", 
            WEB_INTERACTION_AGENT_NAME: "🌐", 
            COORDINATOR_AGENT_NAME: "🧠", 
            PAYLOAD_GENERATOR_AGENT_NAME: "✨" 
        }
        icon = icon_map.get(agent_name, "💬")
        if "System_Error" in agent_name or "SysErr" in agent_name : icon = "🔥" 
        exp_title = f"{icon} {agent_name} ({agent_role}, Lượt {i+1})"
        expanded = (i == len(st.session_state.conversation_log_output) -1) or ("System_Error" in agent_name or "SysErr" in agent_name) or (agent_role in ['function', 'tool'])
        with st.expander(exp_title, expanded=expanded):
            content = msg.get('content', ''); tool_calls = msg.get('tool_calls') 
            if tool_calls and isinstance(tool_calls, list): 
                st.markdown("**Tool Call(s):**")
                for tc_idx, tc in enumerate(tool_calls):
                    func_info = tc.get('function', {}); func_name = func_info.get('name', 'unknown')
                    func_args_str = func_info.get('arguments', '{}'); st.markdown(f"  `{tc_idx+1}. {func_name}`")
                    try: st.json(json.loads(func_args_str))
                    except: st.text(f"     Args: {func_args_str}")
            elif agent_role in ['function', 'tool']: 
                tool_name = msg.get('name', 'unknown_tool'); st.markdown(f"**Return for `{tool_name}`:**")
                try: st.json(json.loads(content))
                except: st.text(content) 
            elif isinstance(content, str) and (content.strip().startswith(("{", "[")) and content.strip().endswith(("}", "]")) ):
                try: st.json(json.loads(content))
                except: 
                    if "<!DOCTYPE html>" in content.lower() or "<html" in content.lower():
                        with st.popover("Xem HTML", use_container_width=True): st.code(content, language="html")
                    else: st.markdown(content, unsafe_allow_html=True)
            else: st.markdown(content, unsafe_allow_html=True)
else: st.info("Chưa có nhật ký.")

if st.session_state.text_report_content:
    file_name_url_part = "unknown"; 
    if main_target_url_input:
        try:
            p_url = urllib.parse.urlparse(main_target_url_input.strip())
            domain = p_url.netloc.replace(":", "_"); path = p_url.path.replace("/", "_").strip("_")
            file_name_url_part = f"{domain}_{path}" if domain else "local_no_domain"
            file_name_url_part = re.sub(r'[^\w\-_.]', '', file_name_url_part)[:50] 
            if not file_name_url_part: file_name_url_part = "sanitized_empty"
        except: file_name_url_part = "error_parsing_url"
    dl_fn = f"BaoCao_XSS_LK_NQ_v12_{file_name_url_part}_{USER_PROVIDED_DATETIME_UTC.replace(':','-').replace(' ','_')}.txt"
    st.download_button(label="📥 Tải Báo Cáo (.txt)", data=st.session_state.text_report_content, file_name=dl_fn, mime="text/plain", key="download_report_v12")
else: st.info("Chưa có báo cáo để tải.")

st.markdown("---"); st.markdown(f"Lê Khoa & Như Quỳnh."); st.caption(f"Phiên (UTC): {USER_PROVIDED_DATETIME_UTC}")