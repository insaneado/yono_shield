// ============================================================================
// YONO SHIELD — SmsAlert Model
// ============================================================================
// Data model representing an intercepted SMS message that has been analyzed
// for phishing indicators. Contains the raw message data from Kotlin and
// the phishing analysis result computed on the Flutter side.
// ============================================================================

/// Threat level for an intercepted SMS message.
enum SmsThreatLevel {
  /// No phishing indicators found
  clean,

  /// Some suspicious keywords but not definitively phishing
  warning,

  /// Strong phishing indicators — high confidence malicious
  phishing,
}

/// Represents an intercepted SMS with phishing analysis.
class SmsAlert {
  /// The sender's phone number or contact name
  final String sender;

  /// The full message body text
  final String messageBody;

  /// The timestamp when the message was intercepted
  final DateTime timestamp;

  /// The assessed threat level after keyword/URL analysis
  final SmsThreatLevel threatLevel;

  /// List of phishing indicators found in the message
  final List<String> detectedIndicators;

  /// The confidence score (0.0 to 1.0) — higher = more likely phishing
  final double confidenceScore;

  const SmsAlert({
    required this.sender,
    required this.messageBody,
    required this.timestamp,
    required this.threatLevel,
    required this.detectedIndicators,
    required this.confidenceScore,
  });

  /// Analyze a raw SMS payload from the Kotlin EventChannel.
  /// Payload format: "SENDER||MESSAGE_BODY"
  factory SmsAlert.analyzeFromPayload(String payload) {
    // Split the payload into sender and message body
    final parts = payload.split('||');
    final sender = parts.isNotEmpty ? parts[0] : 'Unknown';
    final messageBody = parts.length > 1 ? parts.sublist(1).join('||') : payload;

    // Run phishing analysis
    final indicators = <String>[];
    double score = 0.0;

    // ======================================================================
    // PHISHING KEYWORD ANALYSIS
    // Each keyword category contributes to the confidence score.
    // Multiple matches compound the score toward 1.0.
    // ======================================================================

    final lowerBody = messageBody.toLowerCase();

    // URGENCY keywords — Phishing messages create false urgency
    final urgencyKeywords = ['urgent', 'immediately', 'expire', 'expiring',
        'suspended', 'blocked', 'deactivate', 'last chance', 'act now',
        'within 24 hours', 'account will be', 'final warning'];
    for (final kw in urgencyKeywords) {
      if (lowerBody.contains(kw)) {
        indicators.add('Urgency: "$kw"');
        score += 0.2;
        break; // Only count urgency category once
      }
    }

    // KYC / VERIFICATION keywords — Most common Indian banking phish
    final kycKeywords = ['kyc', 'pan card', 'aadhaar', 'aadhar', 'verify your',
        'update your', 'link your', 'complete verification', 'reverify',
        're-verify', 'kyc update', 'kyc verification'];
    for (final kw in kycKeywords) {
      if (lowerBody.contains(kw)) {
        indicators.add('KYC/Verification: "$kw"');
        score += 0.3;
        break;
      }
    }

    // FINANCIAL THREAT keywords — Threaten account/money loss
    final financialKeywords = ['account blocked', 'account suspended',
        'transaction failed', 'unauthorized', 'credit card', 'debit card',
        'bank account', 'transfer', 'refund', 'cashback', 'reward',
        'won prize', 'lottery', 'claim now'];
    for (final kw in financialKeywords) {
      if (lowerBody.contains(kw)) {
        indicators.add('Financial threat: "$kw"');
        score += 0.25;
        break;
      }
    }

    // ACTION keywords — Asks user to click/call/reply
    final actionKeywords = ['click here', 'click below', 'tap here',
        'call now', 'reply with', 'send otp', 'share otp', 'enter otp',
        'download app', 'install', 'open link'];
    for (final kw in actionKeywords) {
      if (lowerBody.contains(kw)) {
        indicators.add('Call-to-action: "$kw"');
        score += 0.15;
        break;
      }
    }

    // URL PRESENCE — Always suspicious in banking context
    final urlRegex = RegExp(
        r'(https?://[^\s]+)|(www\.[^\s]+)|([a-zA-Z0-9-]+\.(ly|io|co|me|cc|tk|ml|ga|cf|gq|top|xyz|click|link|info|live|online|site|fun|icu|buzz|shop)/[^\s]*)',
        caseSensitive: false);
    if (urlRegex.hasMatch(messageBody)) {
      indicators.add('Contains URL/link');
      score += 0.2;
    }

    // SHORT URL — Extra suspicious (bit.ly, tinyurl, etc.)
    final shortUrlRegex = RegExp(
        r'(bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd|buff\.ly|ow\.ly|rebrand\.ly)',
        caseSensitive: false);
    if (shortUrlRegex.hasMatch(messageBody)) {
      indicators.add('Contains shortened URL');
      score += 0.15;
    }

    // Clamp score to 1.0
    score = score.clamp(0.0, 1.0);

    // Determine threat level based on cumulative score
    SmsThreatLevel threatLevel;
    if (score >= 0.5) {
      threatLevel = SmsThreatLevel.phishing;
    } else if (score >= 0.25) {
      threatLevel = SmsThreatLevel.warning;
    } else {
      threatLevel = SmsThreatLevel.clean;
    }

    return SmsAlert(
      sender: sender,
      messageBody: messageBody,
      timestamp: DateTime.now(),
      threatLevel: threatLevel,
      detectedIndicators: indicators,
      confidenceScore: score,
    );
  }
}
