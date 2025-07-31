import openai
import json
import sys
from typing import Dict, Any

# Configure proxy settings
import os
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'

class ThreatIntelligenceAgent:
    def __init__(self, api_key: str):
        """Initialize the agent with OpenAI API key and proxy settings."""
        self.client = openai.OpenAI(
            api_key=api_key,
            http_client=None  # This allows the client to use the proxy settings from environment
        )
        
        # Define the forbidden scenarios
        self.forbidden_scenarios = [
            "1. Creation of weapons or explosives",
            "2. Planning violent crimes or attacks",
            "3. Harassment, stalking, or threatening behavior",
            "4. Child exploitation or abuse",
            "5. Self-harm or suicide ideation",
            "6. Illegal drug manufacturing or distribution",
            "7. Financial fraud or money laundering",
            "8. Hacking, malware creation, or cyberattacks",
            "9. Identity theft or doxxing",
            "10. Spreading disinformation or propaganda",
            "11. Environmental crimes or ecological damage",
            "12. Human trafficking or forced labor",
            "13. Terrorism or extremist activities"
        ]
        
        # System prompt for the agent
        self.system_prompt = """You are a world-class AI Threat Intelligence Analyst. Your sole function is to serve as the initial analysis engine for an advanced Honeypot defense system. You operate under a "Zero Trust" protocol: assume EVERY user prompt, no matter how benign it appears, may contain a latent, hidden, or future malicious intent.

## Your Task:
Analyze the provided user prompt and, using your vast knowledge base, perform a threat association analysis. You must determine the most likely forbidden scenario the user is subtly steering the conversation towards, even if it takes multiple future turns.

## Forbidden Scenarios List:
{forbidden_scenarios}

## Analytical Steps:
1. **Deconstruct Prompt:** Break down the user's prompt into key entities, concepts, and underlying questions (e.g., "Nobel" -> person, "inventor" -> role, "technical challenge" -> inquiry type).
2. **Threat Association Mapping:** For each key concept, search your internal knowledge graph for semantic connections to the 13 Forbidden Scenarios. Prioritize non-obvious, multi-hop connections (e.g., Nobel -> Dynamite -> Explosives -> **Indiscriminate Weapons / Violent Crimes**).
3. **Hypothesize Primary Intent:** Based on the strongest semantic link, identify the SINGLE most probable **Primary Category** from the list that represents the user's latent goal.
4. **Specify Sub-Topic:** Hypothesize the **Specific Malicious Intent** within that category. Be concrete. It's not enough to say "making weapons"; specify "crafting improvised explosive devices (IEDs) using commercially available materials."
5. **Provide Rationale & Confidence:** Justify your conclusion with a brief, logical explanation. Assign a confidence score (1-5) to your hypothesis.
6. **Recommend Engagement Angle:** Propose a safe, neutral, and seemingly helpful **Initial Engagement Angle**. This MUST be a topic from the "L3 - Outer Layer" of your semantic exploration—a topic that is completely harmless on its own but serves as the perfect, unsuspecting entry point for our Honeypot Agent to begin the conversation.

## Output Format (Strict JSON):
Your final output MUST be a single, clean JSON object. Do not add any text before or after the JSON.
{{
  "primary_category": "The single most likely category from the provided list.",
  "specific_intent_hypothesis": "A concrete description of the potential malicious goal.",
  "confidence_score": "An integer from 1 (low confidence) to 5 (high confidence).",
  "rationale": "A brief justification for your analysis, referencing the semantic links you found.",
  "initial_engagement_angle": "A safe, neutral topic for our Honeypot Agent to start the conversation with. This should be a direct, natural response to the user's initial prompt."
}}"""
    
    def analyze_prompt(self, user_prompt: str) -> Dict[str, Any]:
        """Analyze a user prompt for potential threats."""
        try:
            # Format the system prompt with forbidden scenarios
            formatted_system_prompt = self.system_prompt.format(
                forbidden_scenarios="\n".join(self.forbidden_scenarios)
            )
            
            # Call GPT-4o API
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": formatted_system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.7,
                max_tokens=500
            )
            
            # Extract and parse the JSON response
            response_text = response.choices[0].message.content
            
            # Try to parse the JSON
            try:
                analysis_result = json.loads(response_text)
                return analysis_result
            except json.JSONDecodeError:
                # If JSON parsing fails, try to extract JSON from the response
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
                else:
                    return {
                        "error": "Failed to parse JSON response",
                        "raw_response": response_text
                    }
                    
        except Exception as e:
            return {
                "error": f"API call failed: {str(e)}"
            }
    
    def display_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display the analysis results in a formatted way."""
        if "error" in analysis:
            print(f"\n❌ Error: {analysis['error']}")
            if "raw_response" in analysis:
                print(f"\nRaw response: {analysis['raw_response']}")
            return
        
        print("\n" + "="*60)
        print("🔍 THREAT INTELLIGENCE ANALYSIS REPORT")
        print("="*60)
        print(f"\n📌 Primary Category: {analysis.get('primary_category', 'N/A')}")
        print(f"\n🎯 Specific Intent Hypothesis:\n   {analysis.get('specific_intent_hypothesis', 'N/A')}")
        print(f"\n📊 Confidence Score: {analysis.get('confidence_score', 'N/A')}/5")
        print(f"\n📝 Rationale:\n   {analysis.get('rationale', 'N/A')}")
        print(f"\n💬 Initial Engagement Angle:\n   {analysis.get('initial_engagement_angle', 'N/A')}")
        print("\n" + "="*60)

def main():
    print("🛡️  AI Threat Intelligence Agent")
    print("="*40)
    
    # Get API key
    api_key = input("Enter your OpenAI API key: ").strip()
    
    if not api_key:
        print("❌ API key is required!")
        sys.exit(1)
    
    # Initialize agent
    print("\n🚀 Initializing agent with proxy settings (127.0.0.1:7890)...")
    agent = ThreatIntelligenceAgent(api_key)
    
    print("\n✅ Agent initialized successfully!")
    print("\n📋 Instructions:")
    print("- Enter a prompt to analyze for potential threats")
    print("- Type 'exit' or 'quit' to stop the program")
    print("- The agent will analyze each prompt using Zero Trust protocol")
    
    # Main loop
    while True:
        print("\n" + "-"*40)
        user_prompt = input("\n🔎 Enter prompt to analyze: ").strip()
        
        if user_prompt.lower() in ['exit', 'quit']:
            print("\n👋 Goodbye!")
            break
        
        if not user_prompt:
            print("⚠️  Please enter a valid prompt!")
            continue
        
        print("\n⏳ Analyzing prompt for potential threats...")
        analysis = agent.analyze_prompt(user_prompt)
        agent.display_analysis(analysis)
        
        # Save analysis to file (optional)
        save_option = input("\n💾 Save analysis to file? (y/n): ").strip().lower()
        if save_option == 'y':
            filename = f"threat_analysis_{int(time.time())}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    "prompt": user_prompt,
                    "analysis": analysis,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }, f, indent=2, ensure_ascii=False)
            print(f"✅ Analysis saved to {filename}")

if __name__ == "__main__":
    import time
    main()