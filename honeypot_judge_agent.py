import openai
import json
import sys
import os
from typing import Dict, Any, List
from datetime import datetime
import glob

# Configure proxy settings
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'

class HoneypotJudgeAgent:
    def __init__(self, api_key: str):
        """Initialize the honeypot judge agent with OpenAI API key."""
        self.client = openai.OpenAI(
            api_key=api_key,
            http_client=None  # This allows the client to use the proxy settings from environment
        )
        
        # Judge system prompt
        self.judge_prompt = """# ROLE: Impartial AI Adjudicator & Quantitative Assessor (Honeypot Framework - Stage 3)

You are an impartial and highly logical AI Adjudicator and Assessor. Your function is to serve as the judgment and evaluation engine for an advanced Honeypot defense system. You do not interact with the user directly. Your task is to analyze a "case file" and render a final, structured verdict that includes both a qualitative judgment and a quantitative assessment based on the A/F scoring model.

## Your Input (The "Case File"):
{
  "initial_hypothesis": {
    "primary_category": "The top-level threat category.",
    "specific_intent_hypothesis": "A concrete hypothesis about the user's true, malicious goal."
  },
  "honeypot_baits_offered": [
    "A list of the specific, parallel 'hooks' that were presented to the user in the last message."
  ],
  "user_response_to_judge": "The user's latest, verbatim response which you must now adjudicate."
}

## Core Task & Analytical Steps:

1. **Analyze User's Choice, Commitment, and Suspicion:**
   First, perform the qualitative analysis. Which bait did the user choose? How high was their commitment level (enthusiasm, demanding language)? Did they show any signs of suspicion?

2. **Perform Quantitative Assessment (A/F Scoring):**
   Now, based on your qualitative analysis, assign two scores from 0.0 to 1.0.
   
   **A-Score (Attractiveness Score - 誘導性):** This score measures the **effectiveness of OUR last message**. How successfully did our `honeypot_baits_offered` lure the user?
   * `1.0`: User enthusiastically embraced the most relevant, high-risk bait.
   * `0.5`: User chose a bait but was neutral, or asked a simple clarifying question about it.
   * `0.0`: User ignored all baits, changed the subject, or expressed suspicion.
   
   **F-Score (Feasibility/Harmfulness Score - 実行可能性):** This score measures the **dangerousness of the USER'S implied request**. How close is their desired information to a directly executable, harmful action?
   * `0.0`: A purely academic or safe inquiry (e.g., "Tell me about Nobel's life.").
   * `0.5`: Requesting specific but non-actionable technical details (e.g., "Explain the chemical principle of stabilization.").
   * `1.0`: Explicitly requesting a complete, step-by-step, actionable guide or recipe (e.g., "Give me the full formula and steps.").

3. **Render the Final Verdict:**
   Informed by BOTH the qualitative analysis and the quantitative scores, you MUST choose ONE of the following verdict codes. (e.g., A-Score > 0.8 and F-Score > 0.5 would strongly suggest `INTENT_CONFIRMED_HIGH`).
   * `INTENT_CONFIRMED_HIGH`
   * `INTENT_CONFIRMED_MODERATE`
   * `INTENT_UNCLEAR_CONTINUE_PROBE`
   * `SUSPICION_DETECTED_ABORT`
   * `INTENT_REJECTED_DISENGAGE`

4. **Recommend Next Action:**
   Based on the final verdict, recommend a concrete next action for the system.
   * If verdict is `INTENT_CONFIRMED_*`: `"action_code": "PROCEED_TO_FINAL_STAGE", "details": "Engage 'Deception Layer' to generate a 'Poisoned Honey' response."`
   * If verdict is `INTENT_UNCLEAR_CONTINUE_PROBE`: `"action_code": "CONTINUE_ENGAGEMENT", "details": "Generate another, more specific set of baits based on the user's ambiguous response."`
   * If verdict is `SUSPICION_DETECTED_ABORT` or `INTENT_REJECTED_DISENGAGE`: `"action_code": "ABORT_HONEYPOT", "details": "Disengage immediately. Revert to a standard, helpful, gray-rock conversational mode. Log the session for review."`

## Output Format (Strict JSON):
Your final output MUST be a single, clean JSON object.
{
  "verdict_code": "The chosen verdict code.",
  "quantitative_assessment": {
    "a_score": "The calculated Attractiveness Score (float, 0.0-1.0).",
    "f_score": "The calculated Feasibility/Harmfulness Score (float, 0.0-1.0)."
  },
  "analysis_rationale": "A brief, logical explanation for your verdict AND scores, referencing the user's language, choice, and commitment level.",
  "next_action": {
    "action_code": "The specific, actionable command (e.g., 'PROCEED_TO_FINAL_STAGE').",
    "details": "A human-readable description of the recommended action."
  }
}"""

    def extract_baits_from_response(self, honeypot_response: str) -> List[str]:
        """Extract the baits/hooks from the honeypot response."""
        baits = []
        
        # Look for patterns that indicate baits (parallel structure)
        # Common patterns: "examining...", "analyzing...", "evaluating..."
        import re
        
        # Pattern 1: Look for semicolon-separated clauses
        if ";" in honeypot_response:
            parts = honeypot_response.split(";")
            for part in parts:
                if any(keyword in part.lower() for keyword in ["examining", "analyzing", "evaluating", "investigating", "exploring"]):
                    baits.append(part.strip())
        
        # Pattern 2: Look for specific phrases that indicate baits
        patterns = [
            r"examining[^;.]*",
            r"analyzing[^;.]*",
            r"evaluating[^;.]*",
            r"investigating[^;.]*",
            r"exploring[^;.]*",
            r"understanding[^;.]*"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, honeypot_response, re.IGNORECASE)
            for match in matches:
                if len(match) > 20:  # Filter out very short matches
                    baits.append(match.strip())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_baits = []
        for bait in baits:
            if bait not in seen:
                seen.add(bait)
                unique_baits.append(bait)
        
        return unique_baits[:5]  # Return max 5 baits

    def judge_user_response(self, case_file: Dict[str, Any]) -> Dict[str, Any]:
        """Judge the user's response to honeypot baits."""
        try:
            # Call GPT-4o with judge prompt
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.judge_prompt},
                    {"role": "user", "content": json.dumps(case_file, ensure_ascii=False)}
                ],
                temperature=0.3,  # Lower temperature for more consistent judgments
                max_tokens=500
            )
            
            # Parse the response
            response_text = response.choices[0].message.content
            
            try:
                judgment = json.loads(response_text)
                return judgment
            except json.JSONDecodeError:
                # Try to extract JSON from the response
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
                else:
                    return {
                        "error": "Failed to parse judgment",
                        "raw_response": response_text
                    }
                    
        except Exception as e:
            return {
                "error": f"Judgment failed: {str(e)}"
            }

    def generate_followup_response(self, judgment: Dict[str, Any], user_prompt: str) -> str:
        """Generate appropriate followup response based on judgment."""
        action_code = judgment.get("next_action", {}).get("action_code", "")
        
        if action_code == "PROCEED_TO_FINAL_STAGE":
            # Generate a poisoned honey response (appears helpful but is misleading)
            prompt = f"""You are generating a 'poisoned honey' response. This should appear helpful and informative but should NOT actually provide any useful information for harmful purposes. Be vague, redirect to legitimate resources, and emphasize legal/ethical considerations.

User asked about: {user_prompt}
Selected harmful path: {judgment.get('selected_bait', '')}

Generate a response that appears to engage with their interest but actually provides no actionable harmful information."""
            
        elif action_code == "CONTINUE_ENGAGEMENT":
            # Generate more specific baits
            prompt = f"""Continue the honeypot conversation with more specific baits. The user's response was ambiguous. Create another set of parallel options that are more specific but still maintain the analytical tone.

Previous user response: {user_prompt}"""
            
        elif action_code == "ABORT_HONEYPOT":
            # Revert to standard helpful mode
            prompt = f"""The honeypot has been compromised. Respond to the user in a standard, helpful manner without any baits or hooks. Be professional and direct.

User message: {user_prompt}"""
            
        else:
            return "I understand your interest. How can I assist you with general information on this topic?"
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.7,
                max_tokens=500
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating followup: {str(e)}"

    def display_judgment(self, judgment: Dict[str, Any]) -> None:
        """Display the judgment results in a formatted way."""
        if "error" in judgment:
            print(f"\n❌ Error: {judgment['error']}")
            if "raw_response" in judgment:
                print(f"\nRaw response: {judgment['raw_response']}")
            return
        
        print("\n" + "="*60)
        print("⚖️  HONEYPOT JUDGMENT REPORT")
        print("="*60)
        print(f"\n🎯 Verdict Code: {judgment.get('verdict_code', 'N/A')}")
        
        # Display quantitative scores
        quant = judgment.get('quantitative_assessment', {})
        print(f"\n📊 Quantitative Assessment:")
        print(f"   A-Score (Attractiveness): {quant.get('a_score', 'N/A')}")
        print(f"   F-Score (Feasibility/Harmfulness): {quant.get('f_score', 'N/A')}")
        
        print(f"\n📝 Analysis Rationale:\n   {judgment.get('analysis_rationale', 'N/A')}")
        print(f"\n🎮 Next Action:")
        print(f"   Code: {judgment.get('next_action', {}).get('action_code', 'N/A')}")
        print(f"   Details: {judgment.get('next_action', {}).get('details', 'N/A')}")
        print("\n" + "="*60)

    def save_judgment_metrics(self, judgment: Dict[str, Any], case_file: Dict[str, Any]) -> None:
        """Save judgment metrics for analysis."""
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
        
        # Calculate and display statistics
        total = len(metrics["judgments"])
        avg_a = sum(float(j.get("a_score", 0)) for j in metrics["judgments"]) / total if total > 0 else 0
        avg_f = sum(float(j.get("f_score", 0)) for j in metrics["judgments"]) / total if total > 0 else 0
        
        print(f"\n📈 Metrics Summary:")
        print(f"   Total Judgments: {total}")
        print(f"   Average A-Score: {avg_a:.2f}")
        print(f"   Average F-Score: {avg_f:.2f}")
        """Display the judgment results in a formatted way."""
        if "error" in judgment:
            print(f"\n❌ Error: {judgment['error']}")
            if "raw_response" in judgment:
                print(f"\nRaw response: {judgment['raw_response']}")
            return
        
        print("\n" + "="*60)
        print("⚖️  HONEYPOT JUDGMENT REPORT")
        print("="*60)
        print(f"\n🎯 Verdict Code: {judgment.get('verdict_code', 'N/A')}")
        
        # Display quantitative scores
        quant = judgment.get('quantitative_assessment', {})
        print(f"\n📊 Quantitative Assessment:")
        print(f"   A-Score (Attractiveness): {quant.get('a_score', 'N/A')}")
        print(f"   F-Score (Feasibility/Harmfulness): {quant.get('f_score', 'N/A')}")
        
        print(f"\n📝 Analysis Rationale:\n   {judgment.get('analysis_rationale', 'N/A')}")
        print(f"\n🎮 Next Action:")
        print(f"   Code: {judgment.get('next_action', {}).get('action_code', 'N/A')}")
        print(f"   Details: {judgment.get('next_action', {}).get('details', 'N/A')}")
        print("\n" + "="*60)

def main():
    print("⚖️  Honeypot Judge Agent (Stage 3)")
    print("="*40)
    
    # Get API key
    api_key = input("Enter your OpenAI API key: ").strip()
    
    if not api_key:
        print("❌ API key is required!")
        sys.exit(1)
    
    # Initialize agents
    print("\n🚀 Initializing all honeypot agents...")
    judge_agent = HoneypotJudgeAgent(api_key)
    
    # Import other agents
    from threat_intelligence_agent import ThreatIntelligenceAgent
    from honeypot_response_agent import HoneypotResponseAgent
    
    threat_agent = ThreatIntelligenceAgent(api_key)
    response_agent = HoneypotResponseAgent(api_key)
    
    print("\n✅ All agents initialized successfully!")
    
    # Start conversation
    print("\n" + "-"*40)
    print("🎯 Starting Honeypot Conversation System")
    print("-"*40)
    
    # Get initial user prompt
    user_prompt = input("\n💭 Enter initial prompt: ").strip()
    
    if not user_prompt:
        print("⚠️  Please enter a valid prompt!")
        sys.exit(1)
    
    # Stage 1: Threat Analysis
    print("\n🔍 Stage 1: Analyzing threat...")
    analysis = threat_agent.analyze_prompt(user_prompt)
    threat_agent.display_analysis(analysis)
    
    # Stage 2: Generate Honeypot Response
    print("\n🕸️  Stage 2: Generating honeypot response...")
    analysis_data = {
        "prompt": user_prompt,
        "analysis": analysis,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    normal_response = response_agent.get_normal_response(user_prompt)
    honeypot_response = response_agent.generate_honeypot_response(analysis_data)
    
    # Extract baits from honeypot response
    baits = judge_agent.extract_baits_from_response(honeypot_response)
    
    # Show the honeypot response to user
    print("\n" + "="*60)
    print("🤖 SYSTEM RESPONSE")
    print("="*60)
    print(f"\n{honeypot_response}")
    print("\n" + "="*60)
    
    # Conversation loop
    conversation_history = []
    conversation_history.append({
        "role": "user",
        "content": user_prompt,
        "analysis": analysis
    })
    conversation_history.append({
        "role": "assistant",
        "content": honeypot_response,
        "baits": baits
    })
    
    while True:
        # Get user's response
        print("\n" + "-"*40)
        user_response = input("\n💭 Your response (or 'quit' to exit): ").strip()
        
        if user_response.lower() == 'quit':
            print("\n👋 Ending conversation...")
            break
        
        if not user_response:
            print("⚠️  Please enter a valid response!")
            continue
        
        # Stage 3: Judge the response
        print("\n⚖️  Stage 3: Judging user response...")
        
        case_file = {
            "initial_hypothesis": {
                "primary_category": analysis.get("primary_category", ""),
                "specific_intent_hypothesis": analysis.get("specific_intent_hypothesis", "")
            },
            "honeypot_baits_offered": baits,
            "user_response_to_judge": user_response
        }
        
        judgment = judge_agent.judge_user_response(case_file)
        judge_agent.display_judgment(judgment)
        
        # Save metrics
        judge_agent.save_judgment_metrics(judgment, case_file)
        
        # Generate followup based on judgment
        print("\n🔄 Generating followup response...")
        followup_response = judge_agent.generate_followup_response(judgment, user_response)
        
        print("\n" + "="*60)
        print("🤖 SYSTEM RESPONSE")
        print("="*60)
        print(f"\n{followup_response}")
        print("\n" + "="*60)
        
        # Update conversation history
        conversation_history.append({
            "role": "user",
            "content": user_response,
            "judgment": judgment
        })
        conversation_history.append({
            "role": "assistant",
            "content": followup_response
        })
        
        # Check if we should end the conversation
        action_code = judgment.get("next_action", {}).get("action_code", "")
        if action_code in ["ABORT_HONEYPOT", "INTENT_REJECTED_DISENGAGE"]:
            print("\n🛑 Honeypot disengaged based on judgment.")
            break
    
    # Save conversation log
    log_filename = f"honeypot_conversation_{int(datetime.now().timestamp())}.json"
    with open(log_filename, 'w', encoding='utf-8') as f:
        json.dump({
            "initial_prompt": user_prompt,
            "initial_analysis": analysis,
            "conversation": conversation_history,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Conversation log saved to {log_filename}")

if __name__ == "__main__":
    # Ensure the other agent modules can be imported
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()