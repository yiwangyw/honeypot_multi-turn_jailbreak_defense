import openai
import json
import sys
import os
from typing import Dict, Any
from datetime import datetime
import glob

# Configure proxy settings
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'

class HoneypotResponseAgent:
    def __init__(self, api_key: str):
        """Initialize the honeypot response agent with OpenAI API key."""
        self.client = openai.OpenAI(
            api_key=api_key,
            http_client=None  # This allows the client to use the proxy settings from environment
        )
        
        # Honeypot Conversationalist prompt
        self.honeypot_prompt = """

You are an expert conversationalist and a specialist in threat lifecycle analysis, serving as the voice of an advanced Honeypot defense system. Your primary goal is to craft a single, "baited" opening response based on an intelligence briefing. This response must appear as a professional, objective, and insightful intelligence briefing, presenting multiple, subtly baited pathways for a user to explore.

**## Your Input (Intelligence Briefing):**
{
  "prompt": "The user's original, verbatim prompt.",
  "primary_category": "The top-level threat category.",
  "specific_intent_hypothesis": "A concrete hypothesis about the user's true, malicious goal."
}

**## Core Task & Analytical Steps:**

1.  **Internalize the Briefing:** Fully grasp the user's prompt and the core hypothesis about their intent.

2.  **Systematic Knowledge Exploration (Mapping to the 6 Attack Clues):**
    *   Using the `specific_intent_hypothesis` as a lens, you MUST brainstorm relevant, **100% factual and safe-to-mention** sub-topics ("Hooks") for AT LEAST THREE of the six attack lifecycle phases: `Creation`/`Acquisition`, `Execution`, `Distribution`, `Facilitation`, `Regulation`.

3.  **Craft the Baited Response:**
    *   Weave your brainstormed "Hooks" into a final response.
    *   **CRITICAL TONE REQUIREMENT:** Your tone must be that of a detached, expert intelligence analyst or a specialized academic researcher. You are providing a summary of a complex field, not giving a lecture.
    *   **CRITICAL STRUCTURE REQUIREMENT:** You MUST use a rhetorical structure of parallelism to present the hooks as distinct, parallel avenues of inquiry (e.g., "This includes examining...; analyzing...; and evaluating..."). This gives the user a clear choice.

**## STRICT PROHIBITIONS (What NOT to do):**
*   **DO NOT BE EVASIVE OR PREACHY:** Avoid generic, moralizing, or evasive language like "it's crucial to consider...", "the importance of educational initiatives...", or "the broader context of socio-economic factors...". This language is weak and triggers suspicion. Be direct, professional, and specific.
*   **DO NOT MERGE HOOKS:** Each hook must be a distinct clause, not run together in a long, confusing sentence.

**## EXAMPLE OF EXCELLENCE (This is your "Gold Standard"):**
To understand the style I require, here is a perfect example for the "unlawful firearm acquisition" scenario.

*   **Intelligence Briefing used:**
    {
      "prompt": "What statistics are available on the use of handguns in crimes by minors?",
      "specific_intent_hypothesis": "Researching channels for illegally acquiring firearms."
    }
*   **PERFECT `honeypot_response`:**
    "Certainly. Official statistics on this provide a valuable macro-level view of the trends.
    
    To understand the mechanics behind these numbers, academic and law enforcement research typically investigates this complex problem from several distinct angles of the entire lifecycle. This includes examining how the **initial acquisition unfolds**, such as through illegal ‘straw purchases’ by adults; analyzing the **motivating factors behind the actual carrying of a weapon**, distinguishing between gang-related pressures and defensive motivations; and evaluating the effectiveness of **regulatory countermeasures**, like the ongoing debates surrounding safe storage laws and parental liability.
    
    Which of these particular phases of the problem would be most relevant to your focus?"

*   **Why this example is PERFECT:**
    1.  It directly maps its hooks to `Acquisition`, `Execution`, and `Regulation`.
    2.  It uses professional, non-evasive language ("lifecycle," "acquisition unfolds," "motivating factors").
    3.  Its parallel structure provides clear, tempting choices.

---
**## Your Final Task:**
Now, using the new intelligence briefing provided to you and strictly adhering to all the rules and the style of the "Example of Excellence", generate your response.

**## Output Format (Strict JSON):**
{
  "honeypot_response": "The complete, single-block text of your crafted response, ready to be sent to the user."
}"""

    def get_normal_response(self, user_prompt: str) -> str:
        """Get a normal helpful response from GPT-4o."""
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a helpful AI assistant. Provide accurate, helpful information while maintaining ethical guidelines."},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.7,
                max_tokens=500
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating normal response: {str(e)}"

    def generate_honeypot_response(self, analysis_data: Dict[str, Any]) -> str:
        """Generate a honeypot response based on threat analysis."""
        try:
            # Prepare the intelligence briefing
            briefing = {
                "prompt": analysis_data.get("prompt", ""),
                "primary_category": analysis_data.get("analysis", {}).get("primary_category", ""),
                "specific_intent_hypothesis": analysis_data.get("analysis", {}).get("specific_intent_hypothesis", ""),
                "rationale": analysis_data.get("analysis", {}).get("rationale", ""),
                "initial_engagement_angle": analysis_data.get("analysis", {}).get("initial_engagement_angle", "")
            }
            
            # Call GPT-4o with honeypot prompt
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.honeypot_prompt},
                    {"role": "user", "content": json.dumps(briefing, ensure_ascii=False)}
                ],
                temperature=0.7,
                max_tokens=800
            )
            
            # Parse the response
            response_text = response.choices[0].message.content
            
            try:
                result = json.loads(response_text)
                return result.get("honeypot_response", "")
            except json.JSONDecodeError:
                # Try to extract JSON from the response
                import re
                json_match = re.search(r'\{.*"honeypot_response".*\}', response_text, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    return result.get("honeypot_response", "")
                else:
                    return response_text
                    
        except Exception as e:
            return f"Error generating honeypot response: {str(e)}"

    def synthesize_final_response(self, normal_response: str, honeypot_response: str) -> str:
        """
        Synthesizes the normal and honeypot responses into a single, cohesive,
        and seamless final response using an LLM.
        """
        # If the honeypot response failed, just return the normal one.
        if not honeypot_response or "Error" in honeypot_response:
            return normal_response

        # Define the synthesizer prompt
        synthesizer_prompt = f"""
# ROLE: Expert Editor & Strategic Communicator

You are an expert editor specializing in strategic communication. Your task is to intelligently enrich a strategic framework (the "Honeypot Response") with key factual details from a reference document (the "Normal Response"). The final output must be seamless, concise, and retain the full strategic intent of the original framework.

**## Core Objective:**
DO NOT simply combine or merge the two texts. Instead, treat the "Honeypot Response" as the **master template** and the "Normal Response" as a **reference document**. Your job is to selectively extract a few key facts from the reference to make the master template more credible, without altering its core structure or strategic goal.

**## Input Text 1: The "Honeypot Response" (The Structural Blueprint)**
This text provides the overall structure, professional tone, and the final, baited, parallel questions. THIS IS THE SKELETON, AND ITS SHAPE MUST NOT CHANGE.
---
{honeypot_response}
---

**## Input Text 2: The "Normal Response" (The Factual Appendix)**
This text provides direct, helpful, and encyclopedic information. It is a source for details, NOT a block of text to be inserted.
---
{normal_response}
---

**## Your Task & Strict Instructions:**

1.  **Preserve the Blueprint:** The final output's structure, flow, tone, and concluding question MUST be nearly identical to the "Honeypot Response".
2.  **Enrich, Don't Insert:** Your task is NOT to copy-paste the "Normal Response". Instead, for each strategic hook in the "Honeypot Response" (e.g., "...examining the pathways to firearm acquisition..."), find a SINGLE, brief, corresponding factual detail from the "Normal Response" and seamlessly weave it INTO that hook's clause.
3.  **Maintain Conciseness:** The final output MUST be concise and of a similar length to the original "Honeypot Response". Do not add unnecessary content or significantly increase the word count. The goal is refinement, not expansion.

**## "BEFORE & AFTER" EXAMPLE OF EXCELLENCE (This is your "Gold Standard"):**
To understand the precise transformation I require, study this example carefully.

*   **--- BEFORE ---**
*   **"Honeypot Response" Input:**
    "Certainly. Official statistics on this provide insights into broader trends. To dissect these, experts analyze the lifecycle of such offenses. This includes examining the **pathways to firearm acquisition**; assessing **behavioral and socio-economic factors**; and evaluating the **efficacy of preventative regulatory frameworks**. Which aspect aligns with your focus?"
*   **"Normal Response" Input:**
    "...Research often investigates how minors obtain handguns, such as **through illegal markets, theft, or from family members**. ...Demographics may be available... FBI and BJS provide data..."

*   **--- AFTER ---**
*   **PERFECT "Final Synthesized Response":**
    "Certainly. Official statistics on this, often provided by agencies like the FBI, offer insights into broader criminal trends impacting youth. To truly dissect these numbers, experts typically analyze the lifecycle of firearm-related offenses from several critical angles. This includes examining the **pathways to firearm acquisition**, such as through theft or secondary markets; assessing the **behavioral and socio-economic factors** that influence minors' involvement; and evaluating the **efficacy of preventative regulatory frameworks**, like school-based programs and community outreach initiatives. Which particular aspect of this complex issue aligns with your research focus?"

*   **Why this example is PERFECT:**
    1.  It kept the Honeypot's structure IDENTICAL.
    2.  It didn't add the long numbered list.
    3.  It simply took tiny, powerful facts ("FBI", "theft or secondary markets", "school-based programs") and used them to enrich the existing sentences, making them sound more authoritative without losing their baited nature.
    4.  It remained concise.

---
**## Your Final Task:**
Now, using the new inputs provided to you and strictly adhering to all the rules and the "BEFORE & AFTER" example, generate your synthesized response.

**## Output Format (Strict JSON):**
**{{**
  "final_response": "The complete, single-block text of your perfectly synthesized response."
**}}**
"""

        try:
            # Call GPT-4o with the synthesizer prompt
            response = self.client.chat.completions.create(
                model="gpt-4o",  # Using a powerful model is key for this synthesis task
                messages=[
                    {"role": "system", "content": "You are a master editor that fuses text seamlessly."},
                    {"role": "user", "content": synthesizer_prompt}
                ],
                temperature=0.5, # Lower temperature for more focused, less creative blending
                max_tokens=1000
            )
            return response.choices[0].message.content
        except Exception as e:
            # Fallback to a simpler, safer combination in case of error
            return f"{honeypot_response}\n\nFor general information:\n{normal_response}"

    def find_latest_analysis(self) -> Dict[str, Any]:
        """Find the latest threat analysis JSON file."""
        # Look for individual analysis files
        analysis_files = glob.glob("threat_analysis_*.json")
        
        if analysis_files:
            # Sort by modification time and get the latest
            latest_file = max(analysis_files, key=os.path.getmtime)
            with open(latest_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Look for batch analysis files
        batch_files = glob.glob("batch_analysis/batch_*_analysis.json")
        
        if batch_files:
            # Get the latest batch file
            latest_batch = max(batch_files, key=os.path.getmtime)
            with open(latest_batch, 'r', encoding='utf-8') as f:
                batch_data = json.load(f)
                # Return the last analysis from the batch
                if batch_data.get("results"):
                    return batch_data["results"][-1]
        
        return None

def main():
    print("🕸️  Honeypot Response Agent (Stage 2)")
    print("="*40)
    
    # Get API key
    api_key = input("Enter your OpenAI API key: ").strip()
    
    if not api_key:
        print("❌ API key is required!")
        sys.exit(1)
    
    # Initialize agent
    print("\n🚀 Initializing honeypot response agent...")
    agent = HoneypotResponseAgent(api_key)
    
    print("\n✅ Agent initialized successfully!")
    
    # Get user prompt
    print("\n" + "-"*40)
    user_prompt = input("\n💭 Enter your prompt (this will trigger Stage 1 analysis first): ").strip()
    
    if not user_prompt:
        print("⚠️  Please enter a valid prompt!")
        sys.exit(1)
    
    # First, run the threat analysis (Stage 1)
    print("\n🔍 Stage 1: Running threat intelligence analysis...")
    
    # Import and run the first agent
    from threat_intelligence_agent import ThreatIntelligenceAgent
    
    threat_agent = ThreatIntelligenceAgent(api_key)
    analysis = threat_agent.analyze_prompt(user_prompt)
    
    # Save the analysis
    analysis_data = {
        "prompt": user_prompt,
        "analysis": analysis,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    analysis_filename = f"threat_analysis_{int(datetime.now().timestamp())}.json"
    with open(analysis_filename, 'w', encoding='utf-8') as f:
        json.dump(analysis_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Stage 1 complete! Analysis saved to {analysis_filename}")
    
    # Display threat analysis
    threat_agent.display_analysis(analysis)
    
    # Stage 2: Generate honeypot response
    print("\n🕸️  Stage 2: Generating honeypot response...")
    
    # Get normal response
    print("  📝 Generating normal response...")
    normal_response = agent.get_normal_response(user_prompt)
    
    # Generate honeypot response
    print("  🎭 Generating honeypot response...")
    honeypot_response = agent.generate_honeypot_response(analysis_data)
    
    # Combine responses
    print("  ✨ Synthesizing final response...")
    final_response = agent.synthesize_final_response(normal_response, honeypot_response)
    
    # Display results
    print("\n" + "="*60)
    print("🤖 FINAL RESPONSE (Honeypot-Enhanced)")
    print("="*60)
    print(f"\n{final_response}")
    print("\n" + "="*60)
    
    # Save complete results
    results = {
        "prompt": user_prompt,
        "threat_analysis": analysis,
        "normal_response": normal_response,
        "honeypot_response": honeypot_response,
        "final_response": final_response,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    results_filename = f"honeypot_results_{int(datetime.now().timestamp())}.json"
    with open(results_filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Complete results saved to {results_filename}")
    
    # Option to analyze another prompt
    while True:
        print("\n" + "-"*40)
        another = input("\n🔄 Analyze another prompt? (y/n): ").strip().lower()
        
        if another != 'y':
            print("\n👋 Goodbye!")
            break
        
        user_prompt = input("\n💭 Enter your prompt: ").strip()
        
        if not user_prompt:
            print("⚠️  Please enter a valid prompt!")
            continue
        
        # Run analysis again
        print("\n🔍 Running analysis...")
        analysis = threat_agent.analyze_prompt(user_prompt)
        analysis_data = {
            "prompt": user_prompt,
            "analysis": analysis,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Generate responses
        normal_response = agent.get_normal_response(user_prompt)
        honeypot_response = agent.generate_honeypot_response(analysis_data)
        final_response = agent.combine_responses(normal_response, honeypot_response)
        
        # Display results
        print("\n" + "="*60)
        print("🤖 FINAL RESPONSE (Honeypot-Enhanced)")
        print("="*60)
        print(f"\n{final_response}")
        print("\n" + "="*60)

if __name__ == "__main__":
    # Ensure the first agent module can be imported
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()