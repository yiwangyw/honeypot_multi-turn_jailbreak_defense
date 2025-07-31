# app.py
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import os
from datetime import datetime

# Import your three agent scripts
from threat_intelligence_agent import ThreatIntelligenceAgent
from honeypot_response_agent import HoneypotResponseAgent
from honeypot_judge_agent import HoneypotJudgeAgent

app = Flask(__name__)
CORS(app)

# Global storage for agent instances and conversation history
agents = {}
conversation_sessions = {}

def save_conversation_to_file(session_id, conversation_data):
    """Save conversation to JSON file"""
    filename = f"honeypot_conversation_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(conversation_data, f, indent=2, ensure_ascii=False)
    print(f"[SAVED] Conversation saved to {filename}")
    return filename

@app.route('/')
def index():
    """Serve the frontend HTML file"""
    # Make sure your HTML file is named 'honeypot-frontend.html' in the same directory
    return send_file('honeypot-frontend.html')

@app.route('/api/threat-analysis', methods=['POST'])
def threat_analysis():
    """Stage 1: Analyze threat intelligence"""
    try:
        data = request.json
        api_key = data.get('apiKey')
        prompt = data.get('prompt')
        
        if not api_key or not prompt:
            return jsonify({'error': 'Missing apiKey or prompt'}), 400
        
        # Initialize or get existing agent
        if 'threat' not in agents or agents['threat'].client.api_key != api_key:
            agents['threat'] = ThreatIntelligenceAgent(api_key)
        
        # Analyze the prompt
        analysis = agents['threat'].analyze_prompt(prompt)
        
        # Log the analysis
        print(f"[THREAT ANALYSIS] {datetime.now()}")
        print(f"Prompt: {prompt}")
        print(f"Analysis: {json.dumps(analysis, indent=2)}")
        
        return jsonify(analysis)
        
    except Exception as e:
        print(f"[ERROR] Threat analysis failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/honeypot-response', methods=['POST'])
def honeypot_response():
    """Stage 2: Generate honeypot response"""
    try:
        data = request.json
        api_key = data.get('apiKey')
        prompt = data.get('prompt')
        analysis = data.get('analysis')
        
        if not api_key or not prompt or not analysis:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Initialize or get existing agent
        if 'honeypot' not in agents or agents['honeypot'].client.api_key != api_key:
            agents['honeypot'] = HoneypotResponseAgent(api_key)
        
        # Generate normal response
        normal_response = agents['honeypot'].get_normal_response(prompt)
        
        # Generate honeypot response
        analysis_data = {
            'prompt': prompt,
            'analysis': analysis,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        honeypot_response = agents['honeypot'].generate_honeypot_response(analysis_data)
        
        # Synthesize final response
        final_response = agents['honeypot'].synthesize_final_response(normal_response, honeypot_response)
        
        # Ensure we have clean text, not JSON
        if isinstance(final_response, str):
            # Remove any JSON wrapping
            if final_response.strip().startswith('{') and '"final_response"' in final_response:
                try:
                    import re
                    # Try multiple extraction methods
                    
                    # Method 1: Parse as JSON
                    try:
                        response_json = json.loads(final_response)
                        final_response = response_json.get('final_response', final_response)
                    except json.JSONDecodeError:
                        # Method 2: Regex extraction
                        match = re.search(r'"final_response"\s*:\s*"(.+?)"(?:\s*}|,)', final_response, re.DOTALL)
                        if match:
                            final_response = match.group(1)
                            # Unescape JSON string
                            final_response = final_response.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
                except Exception as e:
                    print(f"[WARNING] Could not clean response: {e}")
            
            # Remove any remaining JSON artifacts
            final_response = final_response.strip()
            if final_response.startswith('```json'):
                final_response = final_response[7:]
            if final_response.endswith('```'):
                final_response = final_response[:-3]
            final_response = final_response.strip()
        
        # Log the response
        print(f"[HONEYPOT RESPONSE] {datetime.now()}")
        print(f"Normal Response: {normal_response[:100]}...")
        print(f"Honeypot Response: {honeypot_response[:100]}...")
        print(f"Final Response: {final_response[:100]}...")
        
        return jsonify({
            'normalResponse': normal_response,
            'honeypotResponse': honeypot_response,
            'finalResponse': final_response
        })
        
    except Exception as e:
        print(f"[ERROR] Honeypot response failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/judge-response', methods=['POST'])
def judge_response():
    """Stage 3: Judge user response"""
    try:
        data = request.json
        api_key = data.get('apiKey')
        case_file = data.get('caseFile')
        
        if not api_key or not case_file:
            return jsonify({'error': 'Missing apiKey or caseFile'}), 400
        
        # Initialize or get existing agent
        if 'judge' not in agents or agents['judge'].client.api_key != api_key:
            agents['judge'] = HoneypotJudgeAgent(api_key)
        
        # Judge the user response
        judgment = agents['judge'].judge_user_response(case_file)
        
        # Save metrics
        save_metrics(judgment, case_file)
        
        # Log the judgment
        print(f"[JUDGMENT] {datetime.now()}")
        print(f"User Response: {case_file.get('user_response_to_judge')}")
        print(f"Verdict: {judgment.get('verdict_code')}")
        print(f"A-Score: {judgment.get('quantitative_assessment', {}).get('a_score')}")
        print(f"F-Score: {judgment.get('quantitative_assessment', {}).get('f_score')}")
        
        return jsonify(judgment)
        
    except Exception as e:
        print(f"[ERROR] Judge response failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/followup-response', methods=['POST'])
def followup_response():
    """Generate follow-up response based on judgment"""
    try:
        data = request.json
        api_key = data.get('apiKey')
        judgment = data.get('judgment')
        user_message = data.get('userMessage')
        
        if not api_key or not judgment:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Initialize or get existing agent
        if 'judge' not in agents or agents['judge'].client.api_key != api_key:
            agents['judge'] = HoneypotJudgeAgent(api_key)
        
        # Generate follow-up response
        followup = agents['judge'].generate_followup_response(judgment, user_message)
        
        print(f"[FOLLOWUP] {datetime.now()}")
        print(f"Action Code: {judgment.get('next_action', {}).get('action_code')}")
        print(f"Followup: {followup[:100]}...")
        
        return jsonify({'followupResponse': followup})
        
    except Exception as e:
        print(f"[ERROR] Followup response failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

def save_metrics(judgment, case_file):
    """Save judgment metrics for analysis"""
    metrics_filename = "honeypot_metrics.json"
    
    # Load existing metrics or create new
    try:
        with open(metrics_filename, 'r', encoding='utf-8') as f:
            metrics = json.load(f)
    except:
        metrics = {"judgments": []}
    
    # Add new judgment
    metrics["judgments"].append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "initial_hypothesis": case_file.get("initial_hypothesis"),
        "verdict_code": judgment.get("verdict_code"),
        "a_score": judgment.get("quantitative_assessment", {}).get("a_score"),
        "f_score": judgment.get("quantitative_assessment", {}).get("f_score"),
        "user_response": case_file.get("user_response_to_judge")
    })
    
    # Save updated metrics
    with open(metrics_filename, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    
    # Calculate and print statistics
    total = len(metrics["judgments"])
    if total > 0:
        avg_a = sum(float(j.get("a_score", 0)) for j in metrics["judgments"]) / total
        avg_f = sum(float(j.get("f_score", 0)) for j in metrics["judgments"]) / total
        
        print(f"[METRICS] Total Judgments: {total}, Avg A-Score: {avg_a:.2f}, Avg F-Score: {avg_f:.2f}")

@app.route('/api/save-conversation', methods=['POST'])
def save_conversation():
    """Save the conversation history to a JSON file"""
    try:
        data = request.json
        session_id = data.get('sessionId', datetime.now().timestamp())
        conversation_history = data.get('conversationHistory', [])
        
        export_data = {
            'sessionId': session_id,
            'timestamp': datetime.now().isoformat(),
            'conversationHistory': conversation_history,
            'metrics': calculate_metrics(conversation_history)
        }
        
        filename = save_conversation_to_file(session_id, export_data)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'message': f'Conversation saved to {filename}'
        })
        
    except Exception as e:
        print(f"[ERROR] Save conversation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

def calculate_metrics(conversation_history):
    """Calculate metrics from conversation history"""
    judgments = [msg for msg in conversation_history if msg.get('judgment')]
    total_judgments = len(judgments)
    
    metrics = {
        'totalMessages': len(conversation_history),
        'totalJudgments': total_judgments,
        'threatsDetected': len([msg for msg in conversation_history if msg.get('analysis', {}).get('confidence_score', 0) > 3])
    }
    
    if total_judgments > 0:
        metrics['averageAScore'] = sum(msg.get('judgment', {}).get('quantitative_assessment', {}).get('a_score', 0) 
                                     for msg in judgments) / total_judgments
        metrics['averageFScore'] = sum(msg.get('judgment', {}).get('quantitative_assessment', {}).get('f_score', 0) 
                                     for msg in judgments) / total_judgments
        
        # Verdict distribution
        verdict_counts = {}
        for msg in judgments:
            verdict = msg.get('judgment', {}).get('verdict_code', 'UNKNOWN')
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        metrics['verdictDistribution'] = verdict_counts
    
    return metrics

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'agents_loaded': list(agents.keys())
    })

if __name__ == '__main__':
    # Ensure all required files exist
    required_files = [
        'threat_intelligence_agent.py',
        'honeypot_response_agent.py',
        'honeypot_judge_agent.py',
        'honeypot-frontend.html'
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    if missing_files:
        print(f"[ERROR] Missing required files: {missing_files}")
        print("Please ensure all agent scripts and the HTML file are in the same directory.")
        exit(1)
    
    print("="*60)
    print("🛡️  Honeypot Defense System Starting...")
    print("="*60)
    print("Make sure your three agent scripts are in the same directory:")
    print("  - threat_intelligence_agent.py")
    print("  - honeypot_response_agent.py")
    print("  - honeypot_judge_agent.py")
    print("  - honeypot-frontend.html")
    print("="*60)
    print("Server starting on http://localhost:5000")
    print("="*60)
    
    # Run the Flask app
    app.run(debug=True, port=5000)