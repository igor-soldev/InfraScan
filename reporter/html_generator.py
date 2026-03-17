import os
import json
import base64

def generate_standalone_html(report_dict):
    """
    Generate a standalone HTML report by embedding CSS, JS, and JSON data
    into the existing index.html template.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Paths to assets
    template_path = os.path.join(base_dir, 'templates', 'index.html')
    css_path = os.path.join(base_dir, 'static', 'style.css')
    js_path = os.path.join(base_dir, 'static', 'app.js')
    logo_path = os.path.join(base_dir, 'static', 'images', 'soldevelo.png')
    
    # Read files
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()
            
        with open(js_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
            
        with open(logo_path, 'rb') as f:
            logo_b64 = base64.b64encode(f.read()).decode('utf-8')
    except Exception as e:
        import logging
        logging.error(f"Failed to read assets for HTML generation: {e}")
        return f"<html><body><h1>Error generating HTML report</h1><p>{str(e)}</p></body></html>"

    # Convert JSON data to string
    json_data_str = json.dumps(report_dict)

    # Replace template tags with inline content
    
    # CSS
    css_tag = "{{ url_for('static', filename='style.css') }}?v={{ static_version }}"
    html_content = html_content.replace(
        f'<link rel="stylesheet" href="{css_tag}">', 
        f'<style>\n{css_content}\n</style>'
    )
    
    # JS
    js_tag = "{{ url_for('static', filename='app.js') }}?v={{ static_version }}"
    injected_script = f"""
    <script>
        window.CLI_INJECTED_DATA = {json_data_str};
        {js_content}
    </script>
    """
    html_content = html_content.replace(
        f'<script src="{js_tag}"></script>', 
        injected_script
    )
    
    # Images (base64)
    logo_tag = "{{ url_for('static', filename='images/soldevelo.png') }}"
    logo_data_uri = f"data:image/png;base64,{logo_b64}"
    html_content = html_content.replace(logo_tag, logo_data_uri)
    
    # Links
    index_tag = "{{ url_for('index') }}"
    html_content = html_content.replace(index_tag, "#")
    
    return html_content
