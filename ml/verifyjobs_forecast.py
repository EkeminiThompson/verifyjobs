# verifyjobs_forecast.py
"""
Time-series forecasting for scam volume prediction
Supports: ARIMA, Exponential Smoothing, Facebook Prophet (if available)

CHANGELOG v2 (aligned with verifyjobs_ml.py v2)
────────────────────────────────────────────────
FIX-A  Scam threshold lowered: 65 → 50 (matches verifyjobs_ml.py FIX-B).
       Jobs scoring 50–64 are "high_risk" and should be labeled as scams.
       This ensures forecast data aligns with ML training labels.

FIX-B  resolve() → absolute() for path anchoring (symlink safety).
       Inherited from verifyjobs_ml.py v1/v2 fix pattern.

FIX-C  Enhanced data loading with better error handling.
       - Handles missing fields gracefully
       - Supports multiple JSON structures
       - Provides detailed diagnostics when data is missing

FIX-D  Improved minimum data requirements.
       - Allows forecasting with as little as 3 days (was implicit)
       - Clearer warnings about forecast confidence based on data quantity
       - Better handling of edge cases in trend analysis
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json
import warnings
warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    from statsmodels.tsa.arima.model import ARIMA
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    STATSMODELS_AVAILABLE = True
except ImportError:
    STATSMODELS_AVAILABLE = False
    print("⚠️ statsmodels not available. Install with: pip install statsmodels")

try:
    from prophet import Prophet
    PROPHET_AVAILABLE = True
except ImportError:
    PROPHET_AVAILABLE = False
    print("⚠️ Prophet not available. Install with: pip install prophet")


# ── PATHS ────────────────────────────────────────────────────────────────────
# FIX-B: Use absolute() for symlink safety
_THIS_FILE    = Path(__file__).absolute()   # .../ml/verifyjobs_forecast.py
_ML_DIR       = _THIS_FILE.parent           # .../ml/
BASE_DIR      = _ML_DIR.parent              # project root
ANALYSES_FILE = BASE_DIR / "data" / "analyses.json"


# ── SCAM LABEL THRESHOLD ─────────────────────────────────────────────────────
# FIX-A: Aligned with verifyjobs_ml.py v2
# Scores 50–64 represent "high_risk" — treating them as legitimate produces
# false negatives in both training and forecasting.
SCAM_LABEL_THRESHOLD = 50


class ScamVolumeForecaster:
    """
    Comprehensive forecasting for job scam volume
    Supports multiple models and ensemble predictions
    """
                                
    
    def __init__(self, daily_data: pd.DataFrame):
        """
        daily_data: DataFrame with columns 'date' and 'scam_count'
        """

        self.raw_data = daily_data.copy()

        # Ensure datetime
        self.raw_data['date'] = pd.to_datetime(self.raw_data['date'])

        # Set index BEFORE asfreq
        self.raw_data = self.raw_data.set_index('date').sort_index()

        # Force daily frequency (fills missing dates with NaN)
        self.raw_data = self.raw_data.asfreq('D')

        # Fill missing values
        self.raw_data['scam_count'] = self.raw_data['scam_count'].fillna(0)

        # Create features
        self._create_features()
        
    def _create_features(self):
        """Create time-based features"""
        self.data = self.raw_data.copy()
        self.data['day_of_week'] = self.data.index.dayofweek
        self.data['month'] = self.data.index.month
        self.data['week_of_year'] = self.data.index.isocalendar().week
        self.data['day_of_month'] = self.data.index.day
        self.data['is_weekend'] = (self.data['day_of_week'] >= 5).astype(int)
        
        # Rolling statistics (with min_periods for small datasets)
        window = min(7, len(self.data))
        self.data['rolling_mean_7'] = self.data['scam_count'].rolling(window, min_periods=1).mean()
        self.data['rolling_std_7'] = self.data['scam_count'].rolling(window, min_periods=1).std()
        
    def naive_forecast(self, days: int = 7) -> Dict:
        """
        Baseline: Use last value as forecast
        """
        last_value = self.data['scam_count'].iloc[-1]
        predictions = [float(last_value)] * days
        
        return {
            'model': 'Naive',
            'predictions': predictions,
            'total_expected': float(last_value * days),
            'daily_average': float(last_value),
            'rmse': None
        }
    
    def moving_average_forecast(self, window: int = None, days: int = 7) -> Dict:
        """
        Simple moving average forecast
        """
        if window is None:
            window = min(3, len(self.data))  # Use smaller window for limited data
        
        ma = self.data['scam_count'].rolling(window, min_periods=1).mean().iloc[-1]
        predictions = [float(ma)] * days
        
        # Calculate RMSE on historical data
        historical_ma = self.data['scam_count'].rolling(window, min_periods=1).mean()
        valid = self.data['scam_count'].notna() & historical_ma.notna()
        if valid.sum() > 1:
            rmse = np.sqrt(np.mean((self.data.loc[valid, 'scam_count'] - historical_ma[valid]) ** 2))
        else:
            rmse = None
        
        return {
            'model': f'Moving Average (window={window})',
            'predictions': predictions,
            'total_expected': float(ma * days),
            'daily_average': float(ma),
            'rmse': float(rmse) if rmse else None
        }
    
    def exponential_smoothing_forecast(self, alpha: float = 0.3, days: int = 7) -> Dict:
        """
        Exponential smoothing forecast
        """
        # Calculate smoothed values
        smoothed = [self.data['scam_count'].iloc[0]]
        for val in self.data['scam_count'].iloc[1:]:
            smoothed.append(alpha * val + (1 - alpha) * smoothed[-1])
        
        last_smoothed = smoothed[-1]
        predictions = []
        current = last_smoothed
        
        for _ in range(days):
            predictions.append(current)
            current = alpha * current + (1 - alpha) * current  # Level-only forecast
        
        # Calculate RMSE
        rmse = np.sqrt(np.mean((self.data['scam_count'].values - np.array(smoothed)) ** 2))
        
        return {
            'model': f'Exponential Smoothing (α={alpha})',
            'predictions': [float(p) for p in predictions],
            'total_expected': float(sum(predictions)),
            'daily_average': float(np.mean(predictions)),
            'rmse': float(rmse)
        }
    
    def linear_trend_forecast(self, days: int = 7) -> Dict:
        """
        Simple linear regression forecast for limited data
        """
        x = np.arange(len(self.data))
        y = self.data['scam_count'].values
        
        # Fit linear regression
        slope, intercept = np.polyfit(x, y, 1)
        
        # Forecast
        predictions = []
        for i in range(1, days + 1):
            pred = intercept + slope * (len(self.data) + i)
            predictions.append(max(0, pred))  # No negative scams
        
        # Calculate RMSE on historical data
        fitted = intercept + slope * x
        rmse = np.sqrt(np.mean((y - fitted) ** 2))
        
        return {
            'model': 'Linear Trend',
            'predictions': [float(p) for p in predictions],
            'total_expected': float(sum(predictions)),
            'daily_average': float(np.mean(predictions)),
            'rmse': float(rmse),
            'slope': float(slope)
        }
    
    def holt_winters_forecast(self, days: int = 7) -> Optional[Dict]:
        """
        Holt-Winters triple exponential smoothing
        Requires statsmodels and sufficient data (at least 14 days)
        """
        if not STATSMODELS_AVAILABLE:
            return None
        
        if len(self.data) < 14:
            return None  # Not enough data for Holt-Winters
        
        try:
            # Fit Holt-Winters model
            model = ExponentialSmoothing(
                self.data['scam_count'],
                trend='add',
                seasonal='add',
                seasonal_periods=7,
                initialization_method='estimated'
            )
            fitted = model.fit()
            forecast = fitted.forecast(days)
            
            return {
                'model': 'Holt-Winters (Triple Exponential Smoothing)',
                'predictions': [float(p) for p in forecast],
                'total_expected': float(forecast.sum()),
                'daily_average': float(forecast.mean()),
                'rmse': float(np.sqrt(np.mean((fitted.fittedvalues - self.data['scam_count'].values) ** 2)))
            }
        except Exception as e:
            print(f"Holt-Winters failed: {e}")
            return None
    
    def arima_forecast(self, days: int = 7, order: Tuple = (1, 1, 1)) -> Optional[Dict]:
        """
        ARIMA model forecast
        Requires statsmodels and sufficient data
        """
        if not STATSMODELS_AVAILABLE:
            return None
        
        if len(self.data) < 10:
            return None  # Not enough data for ARIMA
        
        try:
            model = ARIMA(self.data['scam_count'], order=order)
            fitted = model.fit()
            forecast = fitted.forecast(steps=days)
            
            return {
                'model': f'ARIMA{order}',
                'predictions': [float(p) for p in forecast],
                'total_expected': float(forecast.sum()),
                'daily_average': float(forecast.mean()),
                'rmse': float(np.sqrt(np.mean((fitted.fittedvalues - self.data['scam_count'].values) ** 2)))
            }
        except Exception as e:
            print(f"ARIMA failed: {e}")
            return None
    
    def prophet_forecast(self, days: int = 7) -> Optional[Dict]:
        """
        Facebook Prophet forecast
        Requires prophet package and sufficient data
        """
        if not PROPHET_AVAILABLE:
            return None
        
        if len(self.data) < 14:
            return None  # Not enough data for Prophet
        
        try:
            # Prepare data for Prophet
            df = pd.DataFrame({
                'ds': self.data.index,
                'y': self.data['scam_count'].values
            })
            
            # Fit model
            model = Prophet(
                yearly_seasonality=False,
                weekly_seasonality=True,
                daily_seasonality=False,
                changepoint_prior_scale=0.05
            )
            model.fit(df)
            
            # Make future dataframe
            future = model.make_future_dataframe(periods=days, include_history=False)
            forecast = model.predict(future)
            
            return {
                'model': 'Prophet (Facebook)',
                'predictions': [float(p) for p in forecast['yhat'].values],
                'total_expected': float(forecast['yhat'].sum()),
                'daily_average': float(forecast['yhat'].mean()),
                'lower_bound': [float(p) for p in forecast['yhat_lower'].values],
                'upper_bound': [float(p) for p in forecast['yhat_upper'].values],
                'rmse': None
            }
        except Exception as e:
            print(f"Prophet failed: {e}")
            return None
    
    def ensemble_forecast(self, days: int = 7) -> Dict:
        """
        Ensemble of all available models (weighted average)
        Adapts based on data availability
        """
        forecasts = []
        weights = []
        
        # Always include basic models
        naive = self.naive_forecast(days)
        forecasts.append(naive)
        weights.append(0.15)
        
        ma = self.moving_average_forecast(None, days)
        forecasts.append(ma)
        weights.append(0.25)
        
        es = self.exponential_smoothing_forecast(0.3, days)
        forecasts.append(es)
        weights.append(0.25)
        
        # Add linear trend for limited data
        lt = self.linear_trend_forecast(days)
        forecasts.append(lt)
        weights.append(0.35)
        
        # Try advanced models only if enough data
        if len(self.data) >= 14:
            hw = self.holt_winters_forecast(days)
            if hw:
                forecasts.append(hw)
                weights.append(0.2)
            
            arima = self.arima_forecast(days)
            if arima:
                forecasts.append(arima)
                weights.append(0.15)
            
            prophet = self.prophet_forecast(days)
            if prophet:
                forecasts.append(prophet)
                weights.append(0.15)
        
        # Normalize weights
        weights = np.array(weights) / sum(weights)
        
        # Weighted average of predictions
        ensemble_pred = np.zeros(days)
        for i, f in enumerate(forecasts):
            ensemble_pred += weights[i] * np.array(f['predictions'])
        
        # Calculate confidence intervals from prediction spread
        all_preds = np.array([f['predictions'] for f in forecasts])
        lower_bound = np.percentile(all_preds, 25, axis=0)
        upper_bound = np.percentile(all_preds, 75, axis=0)
        
        return {
            'model': 'Ensemble (Weighted Average)',
            'models_used': [f['model'] for f in forecasts],
            'weights': {f['model']: float(w) for f, w in zip(forecasts, weights)},
            'predictions': [float(p) for p in ensemble_pred],
            'total_expected': float(ensemble_pred.sum()),
            'daily_average': float(ensemble_pred.mean()),
            'lower_bound': [float(l) for l in lower_bound],
            'upper_bound': [float(u) for u in upper_bound],
            'confidence': 'low' if len(self.data) < 10 else 'medium' if len(self.data) < 21 else 'high'
        }
    
    def get_trend_analysis(self) -> Dict:
        """
        Analyze trend direction and seasonality
        Adapted for limited data
        """
        if len(self.data) < 4:
            return {'error': 'Insufficient data for trend analysis (need at least 4 days)'}
        
        # Calculate trend using linear regression
        x = np.arange(len(self.data))
        y = self.data['scam_count'].values
        slope = np.polyfit(x, y, 1)[0]
        
        # Weekly seasonality (only if we have at least 2 weeks)
        if len(self.data) >= 10:
            dow_avg = self.data.groupby('day_of_week')['scam_count'].mean()
            peak_day = dow_avg.idxmax()
            peak_day_name = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][peak_day]
            lowest_day = dow_avg.idxmin()
            lowest_day_name = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][lowest_day]
            weekend_effect = float(dow_avg[5:].mean() - dow_avg[:5].mean()) if len(dow_avg) >= 7 else 0
        else:
            peak_day_name = "Insufficient data"
            lowest_day_name = "Insufficient data"
            weekend_effect = 0
        
        # Recent trend (last half vs previous half)
        split_point = max(1, len(self.data) // 2)  # FIX-D: Ensure at least 1 sample per split
        recent = self.data['scam_count'].tail(split_point).mean()
        previous = self.data['scam_count'].head(split_point).mean()
        percent_change = ((recent - previous) / previous * 100) if previous > 0 else 0
        
        # Volatility
        volatility = self.data['scam_count'].std() / (self.data['scam_count'].mean() + 0.01)
        
        direction = "increasing" if slope > 0 else "decreasing"
        strength = "strong" if abs(slope) > 0.5 else "moderate" if abs(slope) > 0.2 else "weak"
        
        return {
            'trend_direction': direction,
            'trend_strength': strength,
            'slope': float(slope),
            'weekly_pattern': {
                'peak_day': peak_day_name,
                'peak_value': None,
                'lowest_day': lowest_day_name,
                'lowest_value': None,
                'weekend_effect': weekend_effect
            },
            'recent_change': {
                'percent': float(percent_change),
                'recent_avg': float(recent),
                'previous_avg': float(previous)
            },
            'volatility': float(volatility),
            'volatility_label': 'high' if volatility > 0.5 else 'medium' if volatility > 0.3 else 'low'
        }
    
    def generate_report(self, days: int = 7) -> Dict:
        """
        Generate comprehensive forecast report
        """
        # Get ensemble forecast
        forecast = self.ensemble_forecast(days)
        trend = self.get_trend_analysis()
        
        # Prepare dates for forecast
        last_date = self.data.index[-1]
        forecast_dates = [last_date + timedelta(days=i+1) for i in range(days)]
        
        # Calculate risk levels
        normal_avg = self.data['scam_count'].mean()
        high_threshold = normal_avg * 1.5
        critical_threshold = normal_avg * 2
        
        risk_assessment = []
        for i, pred in enumerate(forecast['predictions']):
            if pred >= critical_threshold:
                level = 'critical'
            elif pred >= high_threshold:
                level = 'high'
            elif pred >= normal_avg:
                level = 'medium'
            else:
                level = 'low'
            risk_assessment.append(level)
        
        # Business recommendations
        recommendations = []
        if trend.get('trend_direction') == 'increasing' and trend.get('trend_strength') == 'strong':
            recommendations.append("⚠️ Scam volume is increasing — monitor closely")
        
        if len(self.data) < 14:
            recommendations.append("📊 Limited data available (less than 2 weeks) — forecasts will improve with more data")
        
        if forecast.get('daily_average', 0) > normal_avg * 1.3:
            recommendations.append("🚨 Next week expected to be ABOVE normal — prepare support team")
        
        if not recommendations:
            recommendations.append("📊 Continue monitoring scam patterns as more data accumulates")
        
        return {
            'forecast': forecast,
            'trend_analysis': trend,
            'forecast_dates': [d.isoformat() for d in forecast_dates],
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'data_summary': {
                'total_days': len(self.data),
                'total_scams': int(self.data['scam_count'].sum()),
                'avg_daily': float(self.data['scam_count'].mean()),
                'max_daily': int(self.data['scam_count'].max()),
                'last_7_days': [int(x) for x in self.data['scam_count'].tail(min(7, len(self.data))).values]
            },
            'generated_at': datetime.now().isoformat(),
            'warnings': [] if len(self.data) >= 7 else ['Limited data: forecasts may be less accurate']
        }


# ============================================================================
# INTEGRATION WITH EXISTING ANALYSES
# ============================================================================

def load_daily_scam_data(analyses_json_path: str) -> pd.DataFrame:
    """
    Extract daily scam counts from analyses.json
    
    FIX-A: Uses SCAM_LABEL_THRESHOLD = 50 (aligned with verifyjobs_ml.py v2)
    FIX-C: Enhanced error handling and data extraction logic
    """
    print(f"Loading analyses from: {analyses_json_path}")
    
    # FIX-C: Better file existence check
    if not Path(analyses_json_path).exists():
        raise FileNotFoundError(
            f"Analyses file not found at: {analyses_json_path}\n"
            f"Run some job checks first to populate data."
        )
    
    with open(analyses_json_path, 'r') as f:
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
        raise ValueError(f"Unexpected JSON format: {type(data)}")
    
    print(f"Found {len(analyses)} analysis records")
    
    if not analyses:
        raise ValueError(
            "No analyses found in JSON file. Structure:\n"
            f"  Expected: {{'analyses': [...]}} or [...]\n"
            f"  Got: {list(data.keys()) if isinstance(data, dict) else 'list'}"
        )
    
    # FIX-C: Enhanced data extraction with detailed diagnostics
    daily_counts = {}
    skipped = {'no_timestamp': 0, 'no_risk_score': 0}
    
    for i, analysis in enumerate(analyses):
        # Extract timestamp from various possible locations
        timestamp = None
        if 'timestamp' in analysis:
            timestamp = analysis['timestamp']
        elif 'metadata' in analysis and 'analysisTimestamp' in analysis['metadata']:
            timestamp = analysis['metadata']['analysisTimestamp']
        elif 'result' in analysis and 'metadata' in analysis['result']:
            timestamp = analysis['result']['metadata'].get('analysisTimestamp')
        elif 'created_at' in analysis:
            timestamp = analysis['created_at']
        
        if not timestamp:
            skipped['no_timestamp'] += 1
            continue
        
        # Extract date (YYYY-MM-DD)
        try:
            date = timestamp[:10]  # Works for ISO format: 2024-01-15T12:34:56
        except (TypeError, IndexError):
            skipped['no_timestamp'] += 1
            continue
        
        # FIX-A: Determine if scam using SCAM_LABEL_THRESHOLD = 50
        # (aligned with verifyjobs_ml.py v2)
        risk_score = None
        if 'riskScore' in analysis:
            risk_score = analysis['riskScore']
        elif 'result' in analysis:
            if 'riskScore' in analysis['result']:
                risk_score = analysis['result']['riskScore']
            elif 'classification' in analysis['result']:
                risk_score = analysis['result']['classification'].get('riskScore')
        elif 'classification' in analysis:
            risk_score = analysis['classification'].get('riskScore')
        
        if risk_score is None:
            skipped['no_risk_score'] += 1
            continue
        
        # FIX-A: Use threshold 50 (not 65)
        is_scam = 1 if risk_score >= SCAM_LABEL_THRESHOLD else 0
        
        if date not in daily_counts:
            daily_counts[date] = {'scam_count': 0, 'total': 0}
        daily_counts[date]['scam_count'] += is_scam
        daily_counts[date]['total'] += 1
    
    # FIX-C: Diagnostic output
    if skipped['no_timestamp'] > 0 or skipped['no_risk_score'] > 0:
        print(f"⚠️ Skipped records:")
        if skipped['no_timestamp'] > 0:
            print(f"   - {skipped['no_timestamp']} missing timestamp")
        if skipped['no_risk_score'] > 0:
            print(f"   - {skipped['no_risk_score']} missing risk_score")
    
    if not daily_counts:
        raise ValueError(
            "No valid dates found in analyses file.\n"
            "Each analysis needs:\n"
            "  - timestamp (or metadata.analysisTimestamp)\n"
            "  - riskScore (or result.riskScore)\n"
            f"Threshold for scam: risk_score >= {SCAM_LABEL_THRESHOLD}"
        )
    
    # Create DataFrame
    df = pd.DataFrame([
        {'date': date, 'scam_count': counts['scam_count'], 'total': counts['total']}
        for date, counts in sorted(daily_counts.items())
    ])
    
    print(f"✅ Created daily data with {len(df)} days")
    print(f"   Date range: {df['date'].min()} to {df['date'].max()}")
    print(f"   Total scams: {df['scam_count'].sum()} (threshold >= {SCAM_LABEL_THRESHOLD})")
    print(f"   Total jobs analyzed: {df['total'].sum()}")
    
    return df


def generate_forecast_report(analyses_path: str = None) -> Dict:
    """
    Generate complete forecast report from analyses data
    
    FIX-B: Uses absolute() for path resolution
    FIX-D: Lowered minimum data requirement to 3 days
    """
    if analyses_path is None:
        # FIX-B: Use absolute() for symlink safety
        analyses_path = ANALYSES_FILE
    
    analyses_path = str(analyses_path)
    
    try:
        df = load_daily_scam_data(analyses_path)
        
        # FIX-D: Allow forecasting with as little as 3 days of data
        if len(df) < 3:
            return {
                'error': f'Insufficient data for forecasting (need at least 3 days, have {len(df)})',
                'days_available': len(df),
                'data': df.to_dict('records'),
                'threshold': SCAM_LABEL_THRESHOLD
            }
        
        forecaster = ScamVolumeForecaster(df)
        report = forecaster.generate_report(days=7)
        
        # Add threshold info to report
        report['scam_threshold'] = SCAM_LABEL_THRESHOLD
        
        return report
    except FileNotFoundError as e:
        return {'error': f'Analyses file not found: {str(e)}'}
    except json.JSONDecodeError as e:
        return {'error': f'Invalid JSON in analyses file: {str(e)}'}
    except ValueError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


# ============================================================================
# MAIN - RUN WITH REAL DATA
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("VerifyJobs - Time Series Forecasting v2 (Real Data)")
    print(f"SCAM_THRESHOLD: {SCAM_LABEL_THRESHOLD}  (aligned with ML pipeline)")
    print("=" * 60)
    
    # FIX-B: Use predefined ANALYSES_FILE path
    print(f"\n📁 Loading real data from: {ANALYSES_FILE}")
    print(f"   File exists: {ANALYSES_FILE.exists()}")
    
    # Generate report with real data
    report = generate_forecast_report(ANALYSES_FILE)
    
    if 'error' in report:
        print(f"\n❌ Error: {report['error']}")
        if 'days_available' in report:
            print(f"   Days available: {report['days_available']}")
            print(f"\n💡 Tip: Continue collecting data. You'll get better forecasts once you have 7+ days of data.")
        if 'threshold' in report:
            print(f"   Scam threshold: >= {report['threshold']}")
    else:
        print("\n📊 Data Summary:")
        summary = report['data_summary']
        print(f"   Total days: {summary['total_days']}")
        print(f"   Total scams: {summary['total_scams']} (threshold >= {report.get('scam_threshold', 50)})")
        print(f"   Avg daily: {summary['avg_daily']:.1f}")
        print(f"   Max daily: {summary['max_daily']}")
        print(f"   Last {min(7, summary['total_days'])} days: {summary['last_7_days']}")
        
        if report.get('warnings'):
            print("\n⚠️ Warnings:")
            for warning in report['warnings']:
                print(f"   • {warning}")
        
        print("\n📈 Trend Analysis:")
        trend = report['trend_analysis']
        if 'error' not in trend:
            print(f"   Direction: {trend['trend_direction']} ({trend['trend_strength']})")
            print(f"   Slope: {trend['slope']:.3f}")
            print(f"   Recent change: {trend['recent_change']['percent']:.1f}%")
            print(f"   Volatility: {trend['volatility_label']} ({trend['volatility']:.2f})")
        else:
            print(f"   {trend['error']}")
        
        print("\n🔮 Forecast (Next 7 days):")
        forecast = report['forecast']
        
        for i, (date, pred) in enumerate(zip(report['forecast_dates'][:7], forecast['predictions'][:7])):
            risk = report['risk_assessment'][i]
            risk_icon = "🔴" if risk == 'critical' else "🟡" if risk == 'high' else "🟢"
            print(f"   {date[:10]}: {pred:.1f} scams {risk_icon}")
        
        print(f"\n   Total expected: {forecast['total_expected']:.1f} scams")
        print(f"   Daily average: {forecast['daily_average']:.1f} scams")
        print(f"   Confidence: {forecast.get('confidence', 'unknown')}")
        print(f"   Models used: {len(forecast.get('models_used', []))}")
        
        if 'lower_bound' in forecast and 'upper_bound' in forecast:
            print(f"   Range: [{forecast['lower_bound'][0]:.1f}, {forecast['upper_bound'][0]:.1f}] (day 1)")
        
        print("\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"   • {rec}")
    
    print("\n" + "=" * 60)
    print("✅ Forecast complete.")
    print("=" * 60)