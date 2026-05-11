# verifyjobs_recommendations.py
"""
Recommendation engine for job scam patterns
Implements: Content-based filtering, Collaborative filtering, Similarity scoring

CHANGELOG v2 (aligned with verifyjobs_ml.py v2)
────────────────────────────────────────────────
FIX-A  Scam threshold lowered: 65 → 50 (matches verifyjobs_ml.py FIX-B).
       Jobs scoring 50–64 are "high_risk" and should be labeled as scams.
       Updated all risk scoring logic to use threshold 50.

FIX-B  resolve() → absolute() for path anchoring (symlink safety).
       Consistent with verifyjobs_ml.py v2 pattern.

FIX-C  Enhanced data loading with robust error handling.
       - Handles missing analyses.json gracefully
       - Supports multiple JSON structures (list, dict with 'analyses' key)
       - Better extraction of nested result fields
       - Informative warnings instead of silent failures

FIX-D  Improved risk scoring alignment.
       - Uses same risk_score extraction logic as ML pipeline
       - Handles nested result structures (result.riskScore, result.classification.riskScore)
       - Consistent threshold application across all functions
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import json
import re
import warnings


# ── PATHS ────────────────────────────────────────────────────────────────────
# FIX-B: Use absolute() for symlink safety
_THIS_FILE    = Path(__file__).absolute()   # .../ml/verifyjobs_recommendations.py
_ML_DIR       = _THIS_FILE.parent           # .../ml/
BASE_DIR      = _ML_DIR.parent              # project root
ANALYSES_FILE = BASE_DIR / "data" / "analyses.json"


# ── SCAM LABEL THRESHOLD ─────────────────────────────────────────────────────
# FIX-A: Aligned with verifyjobs_ml.py v2
# Scores 50–64 represent "high_risk" — treating them as legitimate produces
# false negatives in recommendations.
SCAM_LABEL_THRESHOLD = 50


class ScamPatternRecommender:
    """
    Recommends similar scam patterns and prevention strategies
    Uses both content-based and collaborative filtering approaches
    """
    
    def __init__(self, analyses_data: List[Dict]):
        """
        analyses_data: List of analysis results from analyses.json
        """
        self.analyses = analyses_data
        self.scam_pattern_db = self._build_pattern_database()
        self.similarity_matrix = None
        
    def _build_pattern_database(self) -> Dict:
        """Build knowledge base of scam patterns"""
        return {
            'patterns': {
                'advance_fee': {
                    'keywords': ['registration fee', 'processing fee', 'starter kit', 'training fee', 
                                'deposit', 'refundable fee', 'security deposit', 'pay upfront',
                                'before', 'advance payment'],
                    'scam_type': 'Advance Fee Fraud',
                    'risk_level': 'critical',
                    'prevention': 'Never pay to get a job. Legitimate employers cover costs.',
                    'reporting': 'EFCC (Nigeria), FTC (USA), Action Fraud (UK)'
                },
                'whatsapp_scam': {
                    'keywords': ['whatsapp', 'telegram', 'only contact', 'text me on', '@gmail.com contact',
                                'signal', 'contact only', 't.me'],
                    'scam_type': 'Messaging App Recruitment',
                    'risk_level': 'high',
                    'prevention': 'Legitimate hiring uses company email domains and formal processes.',
                    'reporting': 'Block and report the number on WhatsApp/Telegram'
                },
                'crypto_investment': {
                    'keywords': ['crypto', 'bitcoin', 'ethereum', 'investment', 'wallet', 'passive income',
                                'daily returns', 'trading', 'coinbase', 'usdt', 'blockchain', 'nft'],
                    'scam_type': 'Cryptocurrency Job Scam',
                    'risk_level': 'critical',
                    'prevention': 'Real jobs don\'t require you to invest or trade cryptocurrency.',
                    'reporting': 'SEC, local financial authorities'
                },
                'task_based': {
                    'keywords': ['complete tasks', 'commission per task', 'reshipping', 'money transfer',
                                'product review', 'click tasks', 'data entry', 'likes and shares',
                                'per task', 'commission'],
                    'scam_type': 'Task/Commission Scam',
                    'risk_level': 'high',
                    'prevention': 'Legitimate remote work pays salary, not per-task commissions.',
                    'reporting': 'Consumer protection agencies'
                },
                'identity_theft': {
                    'keywords': ['bvn', 'nin', 'ssn', 'passport', 'drivers license', 'bank account',
                                'id verification', 'scan your id', 'photo of id', 'national id',
                                'driver\'s license'],
                    'scam_type': 'Identity Theft',
                    'risk_level': 'critical',
                    'prevention': 'Never share sensitive documents before a formal job offer.',
                    'reporting': 'Credit bureaus, police, identity theft protection services'
                },
                'too_good': {
                    'keywords': ['no experience needed', 'work from home', '₦500k per week', '$2000/week',
                                'easy money', 'get rich', 'limited slots', 'urgent hiring', 'asap',
                                'immediate', 'don\'t miss', 'apply today'],
                    'scam_type': 'Unrealistic Promise Scam',
                    'risk_level': 'high',
                    'prevention': 'If it sounds too good to be true, it is. Research market rates.',
                    'reporting': 'Job board, consumer protection'
                },
                'fake_check': {
                    'keywords': ['send you a check', 'deposit this check', 'equipment fee refund',
                                'overpayment refund', 'wire transfer', 'money gram', 'western union'],
                    'scam_type': 'Fake Check Scam',
                    'risk_level': 'critical',
                    'prevention': 'Checks take weeks to fully clear. Never send money from a deposited check.',
                    'reporting': 'Bank, FTC, police'
                },
                'pyramid_recruitment': {
                    'keywords': ['recruit your friends', 'downline', 'team building bonus',
                                'mlm', 'network marketing', 'referral commission', 'multi-level'],
                    'scam_type': 'Pyramid/Ponzi Scheme',
                    'risk_level': 'high',
                    'prevention': 'Real jobs pay for work, not for recruiting others.',
                    'reporting': 'SEC, FTC'
                },
                'free_email': {
                    'keywords': ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com', 
                                '@aol.com', '@protonmail.com'],
                    'scam_type': 'Free Email Domain',
                    'risk_level': 'medium',
                    'prevention': 'Professional companies use their own domain for email.',
                    'reporting': 'Job board where listing was found'
                }
            },
            'prevention_strategies': {
                'verification': 'Search the company name + "scam" or "review"',
                'lookup': 'Check the company on LinkedIn - do real employees work there?',
                'domain_check': 'Company email should match their website domain',
                'call': 'Call the company directly using a number from their official website',
                'payment_rule': 'Never send money, crypto, or gift cards for a job',
                'document_rule': 'Only provide sensitive documents after signed offer letter',
                'urgency_rule': 'Legitimate jobs don\'t pressure you to decide in 24 hours'
            }
        }
    
    def extract_scam_signatures(self, analysis: Dict) -> Dict:
        """
        Extract scam signatures from a single analysis
        Returns: List of matched pattern types and extracted features
        
        FIX-D: Enhanced extraction logic for nested structures
        """
        # Handle both direct analysis and nested result structures
        result = analysis.get('result', analysis)
        text = analysis.get('text', result.get('text', ''))
        
        # Also check red flags
        red_flags = result.get('redFlags', [])
        if isinstance(red_flags, list):
            red_flags_text = ' '.join(red_flags)
        else:
            red_flags_text = str(red_flags)
        
        combined_text = (text + ' ' + red_flags_text).lower()
        
        matched_patterns = []
        for pattern_id, pattern_info in self.scam_pattern_db['patterns'].items():
            for keyword in pattern_info['keywords']:
                if keyword.lower() in combined_text:
                    matched_patterns.append(pattern_id)
                    break
        
        # FIX-D: Extract risk_score using same logic as ML pipeline
        risk_score = None
        if 'riskScore' in result:
            risk_score = result['riskScore']
        elif 'riskScore' in analysis:
            risk_score = analysis['riskScore']
        elif 'classification' in result and isinstance(result['classification'], dict):
            risk_score = result['classification'].get('riskScore')
        
        # Default to 50 if not found (threshold value)
        if risk_score is None:
            risk_score = SCAM_LABEL_THRESHOLD
        
        return {
            'job_title': analysis.get('jobTitle', result.get('jobTitle', 'Unknown')),
            'source': analysis.get('source', result.get('source', 'Unknown')),
            'risk_score': float(risk_score),
            'matched_patterns': list(set(matched_patterns)),
            'red_flag_count': len(red_flags) if isinstance(red_flags, list) else 0,
            'timestamp': analysis.get('timestamp', 
                                    result.get('timestamp', 
                                             result.get('metadata', {}).get('analysisTimestamp',
                                                                           datetime.now().isoformat())))
        }
    
    def find_similar_scams(self, query_text: str, top_k: int = 5) -> List[Dict]:
        """
        Find similar scams based on keyword overlap
        Content-based filtering approach
        """
        query_lower = query_text.lower()
        
        # Score each known scam pattern
        pattern_scores = {}
        for pattern_id, pattern_info in self.scam_pattern_db['patterns'].items():
            score = 0
            for keyword in pattern_info['keywords']:
                if keyword.lower() in query_lower:
                    score += 1
            if score > 0:
                pattern_scores[pattern_id] = score
        
        # Sort by match score
        sorted_patterns = sorted(pattern_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        
        results = []
        for pattern_id, score in sorted_patterns:
            pattern_info = self.scam_pattern_db['patterns'][pattern_id]
            results.append({
                'pattern_id': pattern_id,
                'scam_type': pattern_info['scam_type'],
                'match_score': score,
                'confidence': min(1.0, score / 3),  # 3+ keywords = high confidence
                'risk_level': pattern_info['risk_level'],
                'prevention': pattern_info['prevention'],
                'reporting': pattern_info['reporting'],
                'examples': self._get_example_scams(pattern_id)
            })
        
        return results
    
    def _get_example_scams(self, pattern_id: str, max_examples: int = 3) -> List[str]:
        """
        Extract real examples from analyses
        
        FIX-C: Better handling of missing data
        """
        examples = []
        for analysis in self.analyses:
            try:
                signature = self.extract_scam_signatures(analysis)
                # FIX-A: Use threshold 50 to identify scams
                if (pattern_id in signature['matched_patterns'] and 
                    signature['risk_score'] >= SCAM_LABEL_THRESHOLD):
                    title = signature['job_title']
                    if title and title != 'Unknown' and len(examples) < max_examples:
                        examples.append(title)
            except Exception as e:
                # Skip malformed analysis entries
                continue
        
        return examples if examples else ['No specific examples available']
    
    def get_prevention_advice(self, query_text: str) -> Dict:
        """
        Get targeted prevention advice based on detected patterns
        """
        similar = self.find_similar_scams(query_text, top_k=3)
        
        if not similar:
            return {
                'advice': "No specific scam patterns detected, but always verify job legitimacy.",
                'general_tips': list(self.scam_pattern_db['prevention_strategies'].values()),
                'detected_patterns': [],
                'primary_risk': 'low',
                'prevention_tips': [],
                'reporting_actions': [],
                'verdict': 'VERIFY CAREFULLY',
                'confidence': 0.0
            }
        
        # Aggregate advice from matched patterns
        prevention_tips = []
        reporting_actions = []
        risk_levels = []
        
        for s in similar:
            if s['prevention'] not in prevention_tips:
                prevention_tips.append(s['prevention'])
            if s['reporting'] not in reporting_actions:
                reporting_actions.append(s['reporting'])
            risk_levels.append(s['risk_level'])
        
        # Determine highest risk level
        risk_priority = ['low', 'medium', 'high', 'critical']
        max_risk = max(risk_levels, key=lambda x: risk_priority.index(x))
        
        return {
            'detected_patterns': [s['scam_type'] for s in similar],
            'primary_risk': max_risk,
            'prevention_tips': prevention_tips,
            'reporting_actions': reporting_actions,
            'verdict': 'HIGH RISK - DO NOT PROCEED' if max_risk in ['high', 'critical'] else 'SUSPICIOUS - VERIFY CAREFULLY',
            'confidence': max(s['confidence'] for s in similar)
        }
    
    def collaborative_filtering_recommendations(self, user_history: List[Dict] = None, k: int = 5) -> List[Dict]:
        """
        User-based collaborative filtering
        If we had user accounts, this would recommend similar scams to watch for
        based on what users with similar analysis history found
        
        Currently implements item-item similarity for demonstration
        
        FIX-C: Better error handling for empty analyses
        """
        if user_history is None:
            user_history = []
        
        if not self.analyses:
            return []
        
        # Build co-occurrence matrix of scam patterns
        pattern_counts = defaultdict(int)
        pattern_pairs = defaultdict(int)
        
        for analysis in self.analyses:
            try:
                signature = self.extract_scam_signatures(analysis)
                patterns = signature['matched_patterns']
                
                for p in patterns:
                    pattern_counts[p] += 1
                    
                # Count co-occurrences
                for i, p1 in enumerate(patterns):
                    for p2 in patterns[i+1:]:
                        pair = tuple(sorted([p1, p2]))
                        pattern_pairs[pair] += 1
            except Exception:
                # Skip malformed entries
                continue
        
        if not pattern_counts:
            return []
        
        # Find similar patterns based on co-occurrence (Jaccard-like)
        recommendations = []
        for pattern in pattern_counts:
            similar = []
            for pair, count in pattern_pairs.items():
                if pattern in pair:
                    other = pair[0] if pair[1] == pattern else pair[1]
                    # Confidence = co-occurrences / occurrences of original pattern
                    confidence = count / pattern_counts[pattern]
                    similar.append((other, confidence))
            
            similar.sort(key=lambda x: x[1], reverse=True)
            
            for other, confidence in similar[:k]:
                recommendations.append({
                    'source_pattern': pattern,
                    'related_pattern': other,
                    'confidence': confidence,
                    'scam_type': self.scam_pattern_db['patterns'].get(other, {}).get('scam_type', other)
                })
        
        # Deduplicate and return top recommendations
        seen = set()
        unique_recs = []
        for rec in sorted(recommendations, key=lambda x: -x['confidence']):
            key = f"{rec['source_pattern']}->{rec['related_pattern']}"
            if key not in seen:
                seen.add(key)
                unique_recs.append(rec)
        
        return unique_recs[:k]
    
    def generate_safety_report(self, job_text: str) -> Dict:
        """
        Generate comprehensive safety report for a job posting
        
        FIX-A: Uses threshold 50 for risk scoring
        """
        # Find similar scams
        similar_scams = self.find_similar_scams(job_text)
        prevention = self.get_prevention_advice(job_text)
        
        # Calculate overall risk score (0-100)
        # FIX-A: Adjusted thresholds to align with 50 scam threshold
        risk_score = 0
        if similar_scams:
            weights = {'low': 10, 'medium': 30, 'high': 60, 'critical': 90}
            risk_score = min(100, sum(weights[s['risk_level']] for s in similar_scams) / len(similar_scams))
        
        # Generate checklist
        checklist = [
            {'item': 'Company has professional website', 'required': True},
            {'item': 'Contact uses company email domain', 'required': True},
            {'item': 'No upfront payment requested', 'required': True},
            {'item': 'Salary is realistic for role', 'required': True},
            {'item': 'Interview process is professional', 'required': True},
            {'item': 'Company exists on LinkedIn/Glassdoor', 'required': True},
        ]
        
        # FIX-A: Risk level thresholds aligned with 50 scam threshold
        risk_level = (
            'critical' if risk_score >= 70 else
            'high' if risk_score >= 50 else  # Changed from 50 to align with threshold
            'medium' if risk_score >= 30 else
            'low'
        )
        
        # Recommended action aligned with threshold 50
        recommended_action = (
            'REJECT AND REPORT' if risk_score >= 50 else  # Aligned with SCAM_LABEL_THRESHOLD
            'VERIFY CAREFULLY' if risk_score >= 25 else
            'PROCEED WITH NORMAL CAUTION'
        )
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'detected_patterns': prevention['detected_patterns'],
            'verdict': prevention['verdict'],
            'prevention_tips': prevention['prevention_tips'],
            'reporting_actions': prevention['reporting_actions'],
            'checklist': checklist,
            'similar_scams_found': len(similar_scams) > 0,
            'confirmed_scam_probability': min(1.0, len(similar_scams) * 0.15),
            'recommended_action': recommended_action,
            'scam_threshold': SCAM_LABEL_THRESHOLD  # Include for reference
        }


# ============================================================================
# INTEGRATION WITH MAIN API
# ============================================================================

def initialize_recommender(analyses_path: Path = None) -> Optional[ScamPatternRecommender]:
    """
    Initialize recommender with existing analyses
    
    FIX-B: Uses absolute() path handling
    FIX-C: Enhanced error handling
    """
    if analyses_path is None:
        analyses_path = ANALYSES_FILE
    
    analyses_path = Path(analyses_path)
    
    try:
        if not analyses_path.exists():
            warnings.warn(
                f"Analyses file not found at {analyses_path}. "
                "Recommender initialized with empty dataset. "
                "Run some job checks first to populate data.",
                UserWarning,
                stacklevel=2
            )
            return ScamPatternRecommender([])
        
        with open(analyses_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both list and dict formats
        if isinstance(data, list):
            analyses = data
        elif isinstance(data, dict):
            analyses = data.get('analyses', [])
            if not analyses:
                # Try alternative keys
                analyses = data.get('results', [])
        else:
            warnings.warn(
                f"Unexpected JSON format in {analyses_path}: {type(data)}",
                UserWarning,
                stacklevel=2
            )
            return ScamPatternRecommender([])
        
        recommender = ScamPatternRecommender(analyses)
        print(f"✅ Recommender initialized with {len(analyses)} analyses (threshold >= {SCAM_LABEL_THRESHOLD})")
        return recommender
        
    except json.JSONDecodeError as e:
        warnings.warn(
            f"Invalid JSON in {analyses_path}: {str(e)}",
            UserWarning,
            stacklevel=2
        )
        return ScamPatternRecommender([])
    except Exception as e:
        warnings.warn(
            f"Error loading analyses: {str(e)}",
            UserWarning,
            stacklevel=2
        )
        return ScamPatternRecommender([])


# ============================================================================
# DEMO
# ============================================================================

def demo():
    """Demo the recommendation engine"""
    print("=" * 60)
    print("VerifyJobs - Recommendation Engine v2")
    print(f"SCAM_THRESHOLD: {SCAM_LABEL_THRESHOLD}  (aligned with ML pipeline)")
    print("=" * 60)
    
    # FIX-B: Use predefined ANALYSES_FILE path
    print(f"\n📁 Loading analyses from: {ANALYSES_FILE}")
    print(f"   File exists: {ANALYSES_FILE.exists()}")
    
    # Try to load real data
    recommender = initialize_recommender(ANALYSES_FILE)
    
    if not recommender or not recommender.analyses:
        print("\n⚠️ No analyses found. Using demo data for illustration.")
        # Demo data
        analyses = [
            {
                'result': {
                    'redFlags': ['WhatsApp listed as sole contact', 'Requests upfront payment'],
                    'riskScore': 72
                }, 
                'jobTitle': 'URGENT Data Entry Clerk',
                'source': 'WhatsApp',
                'timestamp': '2026-05-10T10:30:00',
                'text': 'Contact WhatsApp for details. Pay ₦5000 registration fee.'
            },
            {
                'result': {
                    'redFlags': ['Crypto investment required', 'Team building bonus'],
                    'riskScore': 85
                }, 
                'jobTitle': 'Crypto Trader',
                'source': 'Telegram',
                'timestamp': '2026-05-09T14:20:00',
                'text': 'Invest in Bitcoin and earn daily returns. Recruit friends for bonus.'
            },
            {
                'result': {
                    'redFlags': [],
                    'riskScore': 15
                },
                'jobTitle': 'Software Engineer',
                'source': 'LinkedIn',
                'timestamp': '2026-05-08T09:00:00',
                'text': 'Apply through our careers page. Benefits include health insurance.'
            }
        ]
        recommender = ScamPatternRecommender(analyses)
        print(f"   Using {len(analyses)} demo analyses")
    else:
        print(f"   Loaded {len(recommender.analyses)} real analyses")
    
    # Test job posting
    test_job = """
    URGENT HIRING! Work from home data entry. No experience needed. 
    Pay registration fee of ₦5,000 to secure your slot. 
    Contact us on WhatsApp: +234 123 456 7890
    Limited slots available! Don't miss out on this ₦500,000/week opportunity.
    """
    
    print("\n📝 Analyzing job posting...")
    print(f"   Text preview: {test_job[:100].strip()}...")
    
    print("\n🔍 Finding similar scams...")
    similar = recommender.find_similar_scams(test_job)
    if similar:
        for i, s in enumerate(similar[:3], 1):
            print(f"   {i}. {s['scam_type']} (confidence: {s['confidence']:.0%}, risk: {s['risk_level']})")
            print(f"      → {s['prevention']}")
            if s['examples'] and s['examples'][0] != 'No specific examples available':
                print(f"      Examples: {', '.join(s['examples'][:2])}")
    else:
        print("   No specific patterns detected")
    
    print("\n🛡️ Safety Report:")
    report = recommender.generate_safety_report(test_job)
    print(f"   Risk Score: {report['risk_score']:.0f}/100 ({report['risk_level'].upper()})")
    print(f"   Verdict: {report['verdict']}")
    print(f"   Recommended Action: {report['recommended_action']}")
    print(f"   Scam Probability: {report['confirmed_scam_probability']:.0%}")
    print(f"   Threshold: >= {report['scam_threshold']}")
    
    if report['detected_patterns']:
        print(f"\n   Detected Patterns:")
        for pattern in report['detected_patterns'][:3]:
            print(f"   • {pattern}")
    
    if report['prevention_tips']:
        print("\n   Prevention Tips:")
        for tip in report['prevention_tips'][:3]:
            print(f"   • {tip}")
    
    print("\n   Verification Checklist:")
    for item in report['checklist'][:4]:
        check = "🔲" if item['required'] else "🔘"
        print(f"   {check} {item['item']}")
    
    # Collaborative filtering demo
    print("\n🤝 Collaborative Filtering (Pattern Associations):")
    collab = recommender.collaborative_filtering_recommendations(k=5)
    if collab:
        for i, rec in enumerate(collab[:3], 1):
            print(f"   {i}. {rec['scam_type']} often associated with {rec['source_pattern']}")
            print(f"      (confidence: {rec['confidence']:.0%})")
    else:
        print("   Not enough data for collaborative filtering")
    
    print("\n" + "=" * 60)
    print("✅ Demo complete.")
    print("=" * 60)
    
    return recommender, report


if __name__ == "__main__":
    recommender, report = demo()