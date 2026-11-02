/**
 * CodeInsight – Multi-Language Static Code Analysis Platform
 * Client Application Logic & Router
 */

document.addEventListener('DOMContentLoaded', () => {

  // ==========================================================================
  // 1. APPLICATION STATE
  // ==========================================================================
  let currentUser = null;
  let authToken = localStorage.getItem('codeinsight_token') || null;
  let currentReport = null;
  let selectedFindingIndex = -1;
  let currentFilter = 'all';
  const undoStack = []; // Stack of snapshots: { code: string, timestamp: number }
  let activeProposedFix = null;

  // Language Presets for instant interactive testing
  const PRESETS = {
    javascript: [
      {
        id: 'js_common',
        name: 'Common Beginner Traps (Legacy var, Loose ==, NaN)',
        code: `// Common JavaScript Beginner Traps
var userScore = 100;

function verifyScore(score) {
    // 1. Loose equality permits unexpected type coercion
    if (score == "100") {
        console.log('Score matched as string');
    }

    // 2. Direct comparison with NaN is always false (NaN !== NaN)
    if (score == NaN) {
        return false;
    }

    return true;
}`
      },
      {
        id: 'js_syntax',
        name: 'Syntax Error (Unclosed Bracket & Delimiter)',
        code: `// Syntax Error: Unclosed bracket and unterminated string
function renderGreeting(name) {
    const greeting = "Hello, welcome to our site;
    if (name) {
        return greeting + name;
// Missing closing brace for if block and function`
      },
      {
        id: 'js_security',
        name: 'Security Risk (DOM XSS & eval)',
        code: `// Dangerous Code Execution & DOM XSS
function handleComment(userInput) {
    // DOM XSS Vulnerability
    document.getElementById('display').innerHTML = userInput;

    // Code Injection Vulnerability
    const result = eval(userInput);
    return result;
}`
      },
      {
        id: 'js_clean',
        name: 'Clean Modern ES6+ Code (Grade A+)',
        code: `// Clean Modern JavaScript (ES6+)
function calculateTotal(price, taxRate) {
    if (typeof price !== 'number' || typeof taxRate !== 'number') {
        throw new TypeError('Arguments must be numeric');
    }
    const tax = price * taxRate;
    return price + tax;
}

const finalAmount = calculateTotal(100, 0.18);
console.info(\`Final amount: $\${finalAmount}\`);`
      }
    ],

    python: [
      {
        id: 'py_traps',
        name: 'Python Traps (Mutable Default & Bare Except)',
        code: `# Python Beginner Pitfalls
def add_to_cart(item, cart=[]):
    # Bug: Mutable default argument shares list across all calls!
    cart.append(item)
    return cart

try:
    eval("2 + 2")
except:
    # Bare except catches KeyboardInterrupt and masks fatal crashes
    pass`
      },
      {
        id: 'py_clean',
        name: 'Clean Python 3 Code (Grade A+)',
        code: `# Clean Python 3 Example
from typing import List, Optional

def add_to_cart(item: str, cart: Optional[List[str]] = None) -> List[str]:
    """Appends an item to a user cart safely."""
    if cart is None:
        cart = []
    cart.append(item)
    return cart

total_items = add_to_cart("Book")
print(f"Items in cart: {total_items}")`
      }
    ],

    typescript: [
      {
        id: 'ts_checks',
        name: 'TypeScript Checks (Loose Any & Non-null Assertion)',
        code: `// TypeScript Static Analysis
function processData(input: any) {
    // Discouraged: loose 'any' type bypasses compiler verification
    const item = input.value!; // Non-null assertion risk
    return item;
}`
      }
    ],

    html: [
      {
        id: 'html_a11y',
        name: 'HTML Accessibility & Inline JavaScript Flaw',
        code: `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Document</title>
</head>
<body>
  <!-- Missing alt attribute hurts screen readers -->
  <img src="banner.jpg">

  <!-- Inline javascript: handler poses CSP and XSS risk -->
  <a href="javascript:alert('Hello')">Click Me</a>
</body>
</html>`
      }
    ],

    css: [
      {
        id: 'css_perf',
        name: 'CSS Best Practices (!important & Universal Selector)',
        code: `/* CSS Quality Check */
* {
  box-sizing: border-box;
}

.button {
  background-color: #2563EB !important; /* Overuse of !important breaks cascade */
}`
      }
    ],

    java: [
      {
        id: 'java_sec',
        name: 'Java Security (SQL Injection & Insecure Random)',
        code: `import java.sql.*;
import java.util.Random;

public class UserManager {
    public void getUser(Connection conn, String username) throws SQLException {
        // Vulnerable to SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        // Insecure pseudo-random number generator for security tokens
        Random rand = new Random();
        int token = rand.nextInt();
    }
}`
      }
    ],

    c_cpp: [
      {
        id: 'cpp_mem',
        name: 'C/C++ Memory Safety (gets & strcpy Buffer Overflow)',
        code: `#include <stdio.h>
#include <string.h>

void readInput() {
    char buffer[64];
    // Dangerous: gets() has no bounds checking
    gets(buffer);

    char dest[10];
    // Dangerous: strcpy() may overflow dest buffer
    strcpy(dest, buffer);
}`
      }
    ]
  };

  // Human-readable titles for navigation breadcrumbs
  const TAB_NAMES = {
    'login': 'Sign In',
    'register': 'Create Account',
    'forgot-password': 'Password Recovery',
    'user-dashboard': 'User Dashboard',
    'analyzer': 'Code Analyzer',
    'results': 'Analysis Results',
    'security-scanner': 'Security Scanner',
    'suggestions': 'Code Suggestions',
    'languages': 'Language Support',
    'history': 'Analysis History',
    'user-profile': 'User Profile',
    'user-settings': 'User Settings',
    'about': 'About / Help',
    'admin-dashboard': 'Admin Dashboard',
    'admin-profile': 'Admin Profile',
    'admin-users': 'User Management',
    'admin-logs': 'Analysis Logs',
    'admin-reports': 'Reports & Analytics',
    'admin-settings': 'System Settings'
  };

  // ==========================================================================
  // 2. DOM ELEMENT REFERENCES
  // ==========================================================================
  const appSidebar = document.getElementById('appSidebar');
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const btnToggleSidebar = document.getElementById('btnToggleSidebar');
  const btnCloseSidebar = document.getElementById('btnCloseSidebar');

  const topbarCurrentTab = document.getElementById('topbarCurrentTab');
  const pageAlertBox = document.getElementById('pageAlertBox');
  const pageAlertMessage = document.getElementById('pageAlertMessage');

  // Auth UI
  const userNavSection = document.getElementById('userNavSection');
  const adminNavSection = document.getElementById('adminNavSection');
  const authNavSection = document.getElementById('authNavSection');
  const sidebarUserCard = document.getElementById('sidebarUserCard');
  const sideUserName = document.getElementById('sideUserName');
  const sideUserRole = document.getElementById('sideUserRole');
  const sideUserAvatar = document.getElementById('sideUserAvatar');
  const btnSideLogout = document.getElementById('btnSideLogout');

  const btnNavLogin = document.getElementById('btnNavLogin');
  const btnNavRegister = document.getElementById('btnNavRegister');
  const userChip = document.getElementById('userChip');
  const userNameDisplay = document.getElementById('userNameDisplay');
  const userRoleDisplay = document.getElementById('userRoleDisplay');
  const btnNavLogout = document.getElementById('btnNavLogout');
  const btnTopLaunchAnalyzer = document.getElementById('btnTopLaunchAnalyzer');

  // Analyzer UI
  const analyzerLangSelect = document.getElementById('analyzerLangSelect');
  const btnAutoDetectLang = document.getElementById('btnAutoDetectLang');
  const analyzerPresetSelect = document.getElementById('analyzerPresetSelect');
  const analyzerFileInput = document.getElementById('analyzerFileInput');
  const btnClearCode = document.getElementById('btnClearCode');
  const btnCopyCode = document.getElementById('btnCopyCode');
  const btnRunAnalysis = document.getElementById('btnRunAnalysis');
  const analyzerCodeInput = document.getElementById('analyzerCodeInput');
  const editorGutter = document.getElementById('editorGutter');
  const editorCurrentFilename = document.getElementById('editorCurrentFilename');
  const editorStatsLines = document.getElementById('editorStatsLines');
  const editorStatsChars = document.getElementById('editorStatsChars');
  const analyzerStatusPill = document.getElementById('analyzerStatusPill');
  const analyzerNoticeBox = document.getElementById('analyzerNoticeBox');

  // Results UI
  const resultsScoreVal = document.getElementById('resultsScoreVal');
  const resultsGradeVal = document.getElementById('resultsGradeVal');
  const resultsStatusTitle = document.getElementById('resultsStatusTitle');
  const resultsStatusSubtitle = document.getElementById('resultsStatusSubtitle');
  const resultsCountErrors = document.getElementById('resultsCountErrors');
  const resultsCountWarnings = document.getElementById('resultsCountWarnings');
  const resultsCountQuality = document.getElementById('resultsCountQuality');
  const resultsCountSecurity = document.getElementById('resultsCountSecurity');
  const filterAllCount = document.getElementById('filterAllCount');
  const filterErrorCount = document.getElementById('filterErrorCount');
  const filterWarningCount = document.getElementById('filterWarningCount');
  const filterQualityCount = document.getElementById('filterQualityCount');
  const filterSecurityCount = document.getElementById('filterSecurityCount');
  const findingsContainer = document.getElementById('findingsContainer');
  const resultsCodeViewer = document.getElementById('resultsCodeViewer');
  const codeViewerLanguage = document.getElementById('codeViewerLanguage');

  const findingDetailCard = document.getElementById('findingDetailCard');
  const detailBadgeSeverity = document.getElementById('detailBadgeSeverity');
  const detailRuleId = document.getElementById('detailRuleId');
  const detailLocation = document.getElementById('detailLocation');
  const detailTitle = document.getElementById('detailTitle');
  const detailExplanation = document.getElementById('detailExplanation');
  const detailExtraFields = document.getElementById('detailExtraFields');
  const detailWhyItMatters = document.getElementById('detailWhyItMatters');
  const detailLearningConcept = document.getElementById('detailLearningConcept');
  const detailRemediationBox = document.getElementById('detailRemediationBox');
  const detailRemediationText = document.getElementById('detailRemediationText');
  const btnDetailApplyFix = document.getElementById('btnDetailApplyFix');

  const btnExportMarkdown = document.getElementById('btnExportMarkdown');
  const btnExportCsv = document.getElementById('btnExportCsv');
  const btnResultsGoSuggestions = document.getElementById('btnResultsGoSuggestions');

  // Suggestions & Diff Modal
  const suggestionsContainer = document.getElementById('suggestionsContainer');
  const btnUndoFix = document.getElementById('btnUndoFix');
  const undoStackCount = document.getElementById('undoStackCount');
  const diffPreviewModal = document.getElementById('diffPreviewModal');
  const btnCloseDiffModal = document.getElementById('btnCloseDiffModal');
  const btnCancelDiff = document.getElementById('btnCancelDiff');
  const btnConfirmApplyFix = document.getElementById('btnConfirmApplyFix');
  const diffFindingRule = document.getElementById('diffFindingRule');
  const diffBeforeCode = document.getElementById('diffBeforeCode');
  const diffAfterCode = document.getElementById('diffAfterCode');

  // Scan Detail Modal
  const scanDetailModal = document.getElementById('scanDetailModal');
  const btnCloseScanModal = document.getElementById('btnCloseScanModal');
  const btnCloseScanModalBtn = document.getElementById('btnCloseScanModalBtn');
  const btnScanModalLoadInAnalyzer = document.getElementById('btnScanModalLoadInAnalyzer');
  const scanModalTitle = document.getElementById('scanModalTitle');
  const scanModalSubtitle = document.getElementById('scanModalSubtitle');
  const scanModalContent = document.getElementById('scanModalContent');
  let scanModalActiveCode = '';
  let scanModalActiveLang = 'javascript';

  // ==========================================================================
  // 3. ROUTER & TAB SWITCHING
  // ==========================================================================
  function switchTab(tabId) {
    if (!tabId) tabId = 'user-dashboard';

    // RBAC Route Guard: Admin tabs require admin role
    if (tabId.startsWith('admin-')) {
      if (!currentUser || currentUser.role !== 'admin') {
        showPageAlert('Access Denied: Administrator role required to view the Admin Console.', 'error');
        switchTab(currentUser ? 'user-dashboard' : 'login');
        return;
      }
    }

    // Auth Guard: Profile and Settings require logged-in user
    if ((tabId === 'user-profile' || tabId === 'user-settings') && !currentUser) {
      showPageAlert('Please sign in to access your profile and settings.', 'error');
      switchTab('login');
      return;
    }

    // Toggle active nav buttons
    document.querySelectorAll('.sidebar-nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    });

    // Toggle view visibility
    document.querySelectorAll('.tab-content').forEach(view => {
      view.classList.toggle('active', view.id === `tab-${tabId}`);
    });

    // Update topbar breadcrumb
    if (topbarCurrentTab) {
      topbarCurrentTab.textContent = TAB_NAMES[tabId] || (tabId.charAt(0).toUpperCase() + tabId.slice(1));
    }

    // Close mobile drawer if open
    if (appSidebar) appSidebar.classList.remove('open');
    if (sidebarOverlay) sidebarOverlay.classList.remove('open');

    // Update window URL hash
    window.location.hash = tabId;

    // Trigger tab-specific data loading
    onTabActivated(tabId);

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function onTabActivated(tabId) {
    if (tabId === 'user-dashboard') {
      loadUserDashboardMetrics();
    } else if (tabId === 'history') {
      loadUserHistory();
    } else if (tabId === 'languages') {
      loadLanguagesCatalog();
    } else if (tabId === 'user-profile') {
      populateUserProfileView();
    } else if (tabId === 'user-settings') {
      populateUserSettingsView();
    } else if (tabId === 'admin-dashboard') {
      loadAdminDashboard();
    } else if (tabId === 'admin-users') {
      loadAdminUsers();
    } else if (tabId === 'admin-logs') {
      loadAdminLogs();
    } else if (tabId === 'admin-reports') {
      loadAdminReports();
    } else if (tabId === 'admin-settings') {
      loadAdminSettings();
    } else if (tabId === 'admin-profile') {
      populateAdminProfileView();
    }
  }

  // Bind all nav buttons
  document.querySelectorAll('.sidebar-nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.dataset.tab);
    });
  });

  // Topbar and quick jump actions
  if (btnTopLaunchAnalyzer) btnTopLaunchAnalyzer.addEventListener('click', () => switchTab('analyzer'));
  if (btnNavLogin) btnNavLogin.addEventListener('click', () => switchTab('login'));
  if (btnNavRegister) btnNavRegister.addEventListener('click', () => switchTab('register'));
  if (userChip) userChip.addEventListener('click', () => switchTab(currentUser && currentUser.role === 'admin' ? 'admin-profile' : 'user-profile'));
  if (sidebarUserCard) sidebarUserCard.addEventListener('click', () => switchTab(currentUser && currentUser.role === 'admin' ? 'admin-profile' : 'user-profile'));

  // Dashboard quick tiles
  const btnDashNewScan = document.getElementById('btnDashNewScan');
  if (btnDashNewScan) btnDashNewScan.addEventListener('click', () => switchTab('analyzer'));
  const tileGoAnalyzer = document.getElementById('tileGoAnalyzer');
  if (tileGoAnalyzer) tileGoAnalyzer.addEventListener('click', () => switchTab('analyzer'));
  const tileGoSecurity = document.getElementById('tileGoSecurity');
  if (tileGoSecurity) tileGoSecurity.addEventListener('click', () => switchTab('security-scanner'));
  const tileGoLanguages = document.getElementById('tileGoLanguages');
  if (tileGoLanguages) tileGoLanguages.addEventListener('click', () => switchTab('languages'));
  const tileGoHistory = document.getElementById('tileGoHistory');
  if (tileGoHistory) tileGoHistory.addEventListener('click', () => switchTab('history'));
  const btnDashViewAllHistory = document.getElementById('btnDashViewAllHistory');
  if (btnDashViewAllHistory) btnDashViewAllHistory.addEventListener('click', () => switchTab('history'));

  // Admin tiles
  const adminTileUsers = document.getElementById('adminTileUsers');
  if (adminTileUsers) adminTileUsers.addEventListener('click', () => switchTab('admin-users'));
  const adminTileLogs = document.getElementById('adminTileLogs');
  if (adminTileLogs) adminTileLogs.addEventListener('click', () => switchTab('admin-logs'));
  const adminTileReports = document.getElementById('adminTileReports');
  if (adminTileReports) adminTileReports.addEventListener('click', () => switchTab('admin-reports'));
  const adminTileSettings = document.getElementById('adminTileSettings');
  if (adminTileSettings) adminTileSettings.addEventListener('click', () => switchTab('admin-settings'));

  // Mobile sidebar drawer toggles
  if (btnToggleSidebar) {
    btnToggleSidebar.addEventListener('click', () => {
      appSidebar.classList.toggle('open');
      sidebarOverlay.classList.toggle('open');
    });
  }
  if (btnCloseSidebar) {
    btnCloseSidebar.addEventListener('click', () => {
      appSidebar.classList.remove('open');
      sidebarOverlay.classList.remove('open');
    });
  }
  if (sidebarOverlay) {
    sidebarOverlay.addEventListener('click', () => {
      appSidebar.classList.remove('open');
      sidebarOverlay.classList.remove('open');
    });
  }

  // ==========================================================================
  // 4. ALERTS & TOAST FEEDBACK
  // ==========================================================================
  function showPageAlert(message, type = 'info') {
    if (!pageAlertBox || !pageAlertMessage) return;
    pageAlertMessage.textContent = message;
    pageAlertBox.className = `page-alert ${type}`;
    pageAlertBox.style.display = 'flex';
    setTimeout(() => {
      pageAlertBox.style.display = 'none';
    }, 6000);
  }

  // ==========================================================================
  // 5. AUTHENTICATION & USER SESSION
  // ==========================================================================
  async function checkSession() {
    if (!authToken) {
      applyLoggedOutUI();
      return;
    }

    try {
      const res = await fetch('/api/auth/me', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.user) {
        currentUser = data.user;
        applyLoggedInUI();
      } else {
        localStorage.removeItem('codeinsight_token');
        authToken = null;
        applyLoggedOutUI();
      }
    } catch (e) {
      console.warn('Session check fallback to offline/guest mode:', e);
      applyLoggedOutUI();
    }
  }

  function applyLoggedInUI() {
    if (!currentUser) return;

    if (btnNavLogin) btnNavLogin.style.display = 'none';
    if (btnNavRegister) btnNavRegister.style.display = 'none';
    if (btnNavLogout) btnNavLogout.style.display = 'inline-flex';
    if (btnSideLogout) btnSideLogout.style.display = 'inline-flex';
    if (authNavSection) authNavSection.style.display = 'none';

    if (userChip) {
      userChip.style.display = 'inline-flex';
      if (userNameDisplay) userNameDisplay.textContent = currentUser.name || currentUser.username;
      if (userRoleDisplay) {
        userRoleDisplay.textContent = currentUser.role.toUpperCase();
        userRoleDisplay.className = `role-pill role-${currentUser.role}`;
      }
    }

    if (sideUserName) sideUserName.textContent = currentUser.name || currentUser.username;
    if (sideUserRole) {
      sideUserRole.textContent = currentUser.role.toUpperCase();
      sideUserRole.className = `sidebar-user-role role-${currentUser.role}`;
    }
    if (sideUserAvatar) {
      sideUserAvatar.textContent = (currentUser.avatar || currentUser.name || currentUser.username || 'U').slice(0, 2).toUpperCase();
    }

    // Role-dependent admin section display
    if (adminNavSection) {
      adminNavSection.style.display = currentUser.role === 'admin' ? 'block' : 'none';
    }
  }

  function applyLoggedOutUI() {
    currentUser = null;
    if (btnNavLogin) btnNavLogin.style.display = 'inline-flex';
    if (btnNavRegister) btnNavRegister.style.display = 'inline-flex';
    if (btnNavLogout) btnNavLogout.style.display = 'none';
    if (btnSideLogout) btnSideLogout.style.display = 'none';
    if (userChip) userChip.style.display = 'none';
    if (authNavSection) authNavSection.style.display = 'block';

    if (sideUserName) sideUserName.textContent = 'Guest User';
    if (sideUserRole) sideUserRole.textContent = 'GUEST';
    if (sideUserAvatar) sideUserAvatar.textContent = 'GU';

    if (adminNavSection) adminNavSection.style.display = 'none';
  }

  // Demo-account buttons fill the fields only; they never sign in automatically.
  document.querySelectorAll('[data-demo-username][data-demo-password]').forEach((button) => {
    button.addEventListener('click', () => {
      const identifierInput = document.getElementById('loginIdentifier');
      const passwordInput = document.getElementById('loginPassword');
      if (!identifierInput || !passwordInput) return;
      identifierInput.value = button.dataset.demoUsername || '';
      passwordInput.value = button.dataset.demoPassword || '';
      identifierInput.focus();
    });
  });

  // Login Form
  const formLogin = document.getElementById('formLogin');
  const loginFeedback = document.getElementById('loginFeedback');
  if (formLogin) {
    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const identifier = document.getElementById('loginIdentifier').value.trim();
      const password = document.getElementById('loginPassword').value;

      loginFeedback.style.display = 'none';

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ identifier, password })
        });
        const data = await res.json();
        if (data.success && data.token) {
          authToken = data.token;
          currentUser = data.user;
          localStorage.setItem('codeinsight_token', authToken);
          applyLoggedInUI();
          showPageAlert(`Welcome back, ${currentUser.name || currentUser.username}!`, 'success');

          // Redirect based on backend role
          if (currentUser.role === 'admin') {
            switchTab('admin-dashboard');
          } else {
            switchTab('user-dashboard');
          }
        } else {
          loginFeedback.textContent = data.message || data.error || 'Authentication failed. Please verify credentials.';
          loginFeedback.className = 'feedback-msg error';
          loginFeedback.style.display = 'block';
        }
      } catch (err) {
        loginFeedback.textContent = err && err.message ? `Sign in failed: ${err.message}` : 'Network or server error during sign in.';
        loginFeedback.className = 'feedback-msg error';
        loginFeedback.style.display = 'block';
      }
    });
  }

  // Registration Form
  const formRegister = document.getElementById('formRegister');
  const registerFeedback = document.getElementById('registerFeedback');
  if (formRegister) {
    formRegister.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fullName = document.getElementById('regFullName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const password = document.getElementById('regPassword').value;
      const confirmPassword = document.getElementById('regConfirmPassword').value;

      registerFeedback.style.display = 'none';

      if (password !== confirmPassword) {
        registerFeedback.textContent = 'Passwords do not match.';
        registerFeedback.className = 'feedback-msg error';
        registerFeedback.style.display = 'block';
        return;
      }

      try {
        const username = email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_');
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password, name: fullName })
        });
        const data = await res.json();
        if (data.success) {
          showPageAlert('Registration successful! Please sign in with your credentials.', 'success');
          document.getElementById('loginIdentifier').value = email;
          switchTab('login');
        } else {
          registerFeedback.textContent = data.error || 'Registration failed.';
          registerFeedback.className = 'feedback-msg error';
          registerFeedback.style.display = 'block';
        }
      } catch (err) {
        registerFeedback.textContent = 'Network error during registration.';
        registerFeedback.className = 'feedback-msg error';
        registerFeedback.style.display = 'block';
      }
    });
  }

  // Forgot Password: Step 1 (Request Reset Token)
  const formRequestResetToken = document.getElementById('formRequestResetToken');
  const forgotFeedback = document.getElementById('forgotFeedback');
  if (formRequestResetToken) {
    formRequestResetToken.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('forgotEmail').value.trim();
      forgotFeedback.style.display = 'none';

      try {
        const res = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        forgotFeedback.textContent = data.message || 'Password recovery request processed.';
        forgotFeedback.className = res.ok ? 'feedback-msg success' : 'feedback-msg error';
        forgotFeedback.style.display = 'block';
      } catch (err) {
        forgotFeedback.textContent = 'Server error during password recovery request.';
        forgotFeedback.className = 'feedback-msg error';
        forgotFeedback.style.display = 'block';
      }
    });
  }

  // Forgot Password: Step 2 (Apply Reset Token)
  const formApplyResetToken = document.getElementById('formApplyResetToken');
  const resetFeedback = document.getElementById('resetFeedback');
  if (formApplyResetToken) {
    formApplyResetToken.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = document.getElementById('resetTokenInput').value.trim();
      const newPassword = document.getElementById('resetNewPassword').value;
      const confirmPassword = document.getElementById('resetConfirmPassword').value;
      resetFeedback.style.display = 'none';

      if (newPassword !== confirmPassword) {
        resetFeedback.textContent = 'Passwords do not match.';
        resetFeedback.className = 'feedback-msg error';
        resetFeedback.style.display = 'block';
        return;
      }

      try {
        const res = await fetch('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, newPassword })
        });
        const data = await res.json();
        if (data.success) {
          showPageAlert('Password successfully reset! You can now sign in.', 'success');
          formApplyResetToken.reset();
          switchTab('login');
        } else {
          resetFeedback.textContent = data.error || 'Invalid or expired reset token.';
          resetFeedback.className = 'feedback-msg error';
          resetFeedback.style.display = 'block';
        }
      } catch (err) {
        resetFeedback.textContent = 'Error resetting password.';
        resetFeedback.className = 'feedback-msg error';
        resetFeedback.style.display = 'block';
      }
    });
  }

  // Logout Handlers
  async function performLogout() {
    try {
      if (authToken) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
      }
    } catch (e) {}

    localStorage.removeItem('codeinsight_token');
    authToken = null;
    applyLoggedOutUI();
    showPageAlert('You have been signed out successfully.', 'info');
    switchTab('login');
  }

  if (btnNavLogout) btnNavLogout.addEventListener('click', performLogout);
  if (btnSideLogout) btnSideLogout.addEventListener('click', performLogout);
  const btnProfLogout = document.getElementById('btnProfLogout');
  if (btnProfLogout) btnProfLogout.addEventListener('click', performLogout);

  // ==========================================================================
  // 6. CODE ANALYZER WORKBENCH
  // ==========================================================================
  function updateEditorStats() {
    const code = analyzerCodeInput.value;
    const lines = code.split('\n');
    const lineCount = lines.length;
    const charCount = code.length;

    if (editorStatsLines) editorStatsLines.textContent = `Lines: ${lineCount}`;
    if (editorStatsChars) editorStatsChars.textContent = `Chars: ${charCount}`;

    // Update gutter line numbers
    if (editorGutter) {
      let gutterHtml = '';
      for (let i = 1; i <= lineCount; i++) {
        gutterHtml += `<div class="gutter-line">${i}</div>`;
      }
      editorGutter.innerHTML = gutterHtml;
    }
  }

  function persistWorkingDraft() {
    try {
      if (analyzerCodeInput) localStorage.setItem('codeinsight_working_code', analyzerCodeInput.value);
      if (analyzerLangSelect) localStorage.setItem('codeinsight_working_language', analyzerLangSelect.value);
    } catch (storageError) {
      console.warn('Could not persist working draft.', storageError);
    }
  }

  if (analyzerCodeInput) {
    analyzerCodeInput.addEventListener('input', () => {
      updateEditorStats();
      persistWorkingDraft();
    });
    analyzerCodeInput.addEventListener('scroll', () => {
      if (editorGutter) editorGutter.scrollTop = analyzerCodeInput.scrollTop;
    });
  }

  // Populate Presets based on selected language
  function populatePresetsForLang(lang) {
    if (!analyzerPresetSelect) return;
    analyzerPresetSelect.innerHTML = '<option value="">Load Sample Snippet...</option>';
    const list = PRESETS[lang] || [];
    list.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = p.name;
      analyzerPresetSelect.appendChild(opt);
    });
  }

  if (analyzerLangSelect) {
    analyzerLangSelect.addEventListener('change', () => {
      const lang = analyzerLangSelect.value;
      persistWorkingDraft();
      populatePresetsForLang(lang);
      if (editorCurrentFilename) {
        const extMap = { javascript: 'js', python: 'py', typescript: 'ts', html: 'html', css: 'css', java: 'java', c_cpp: 'cpp' };
        editorCurrentFilename.textContent = `snippet.${extMap[lang] || 'txt'}`;
      }
      // Highlight sidebar lang pill
      document.querySelectorAll('.lang-pill').forEach(pill => {
        pill.classList.toggle('active', pill.dataset.lang === lang);
      });
    });
  }

  // Sidebar language pills click
  document.querySelectorAll('.lang-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const lang = pill.dataset.lang;
      if (analyzerLangSelect) {
        analyzerLangSelect.value = lang;
        analyzerLangSelect.dispatchEvent(new Event('change'));
      }
      switchTab('analyzer');
    });
  });

  if (analyzerPresetSelect) {
    analyzerPresetSelect.addEventListener('change', () => {
      const selectedId = analyzerPresetSelect.value;
      if (!selectedId) return;
      const lang = analyzerLangSelect.value;
      const list = PRESETS[lang] || [];
      const item = list.find(p => p.id === selectedId);
      if (item) {
        analyzerCodeInput.value = item.code;
        updateEditorStats();
        recordSnapshot('Preset: ' + item.name);
      }
    });
  }

  // Auto-Detect Language button
  if (btnAutoDetectLang) {
    btnAutoDetectLang.addEventListener('click', () => {
      const code = analyzerCodeInput.value;
      const detected = detectLanguage(code);
      if (detected && analyzerLangSelect) {
        analyzerLangSelect.value = detected;
        analyzerLangSelect.dispatchEvent(new Event('change'));
        showPageAlert(`Auto-detected language: ${detected.toUpperCase()}`, 'info');
      } else {
        showPageAlert('Could not conclusively determine language. Please select manually.', 'warning');
      }
    });
  }

  function detectLanguage(code) {
    if (!code || code.trim().length === 0) return 'javascript';
    if (/^\s*<!DOCTYPE\s+html/i.test(code) || /<html[\s>]/i.test(code) || /<body[\s>]/i.test(code)) return 'html';
    if (/^\s*(import\s+typing|def\s+[a-zA-Z0-9_]+\s*\(|from\s+[a-zA-Z0-9_.]+\s+import)/m.test(code)) return 'python';
    if (/#include\s*<[a-zA-Z0-9_.]+>|\bint\s+main\s*\([^)]*\)\s*\{/.test(code)) return 'c_cpp';
    if (/\bpublic\s+class\s+[a-zA-Z0-9_]+|\bimport\s+java\./.test(code)) return 'java';
    if (/\binterface\s+[a-zA-Z0-9_]+<|\btype\s+[a-zA-Z0-9_]+\s*=|:\s*(string|number|boolean|any)\[\]/.test(code)) return 'typescript';
    if (/^[.#][a-zA-Z0-9_-]+\s*\{|\b(margin|padding|background|display):\s*[^;]+;/m.test(code)) return 'css';
    return 'javascript';
  }

  // Clear Code
  if (btnClearCode) {
    btnClearCode.addEventListener('click', () => {
      analyzerCodeInput.value = '';
      updateEditorStats();
      analyzerPresetSelect.value = '';
      showPageAlert('Code editor cleared.', 'info');
    });
  }

  // Copy Code
  if (btnCopyCode) {
    btnCopyCode.addEventListener('click', () => {
      const code = analyzerCodeInput.value;
      if (!code) {
        showPageAlert('Editor is empty.', 'warning');
        return;
      }
      navigator.clipboard.writeText(code).then(() => {
        showPageAlert('Code copied to clipboard!', 'success');
      });
    });
  }

  // File / ZIP Upload
  if (analyzerFileInput) {
    analyzerFileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      if (/\.zip$/i.test(file.name)) {
        // The backend expects a JSON base64 payload, not multipart FormData.
        const maxZipBytes = 15 * 1024 * 1024;
        if (file.size > maxZipBytes) {
          showPageAlert('ZIP file is too large. The maximum archive size is 15 MB.', 'warning');
          analyzerFileInput.value = '';
          return;
        }

        showPageAlert(`Processing ZIP archive: ${file.name}...`, 'info');
        try {
          const bytes = new Uint8Array(await file.arrayBuffer());
          let binary = '';
          const chunkSize = 0x8000;
          for (let offset = 0; offset < bytes.length; offset += chunkSize) {
            binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length)));
          }
          const zipBase64 = window.btoa(binary);
          const res = await fetch('/api/analyze/zip', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
            },
            body: JSON.stringify({ zipBase64, filename: file.name })
          });
          const data = await res.json();
          if (res.ok && data.success) {
            // Show the first file in the code viewer; findings retain each source filename.
            const firstFile = Array.isArray(data.files) ? data.files[0] : null;
            if (firstFile) {
              analyzerCodeInput.value = firstFile.content || '';
              updateEditorStats();
              if (analyzerLangSelect) {
                analyzerLangSelect.value = firstFile.language || 'javascript';
                analyzerLangSelect.dispatchEvent(new Event('change'));
              }
              if (editorCurrentFilename) editorCurrentFilename.textContent = firstFile.name;
            }
            renderAnalysisReport(data);
            analyzerStatusPill.textContent = `Project score: ${data.score}/100`;
            analyzerStatusPill.className = 'badge badge-success';
            showPageAlert(`Analyzed ${data.fileCount} source files. ${data.findings.length} finding(s) detected.`, 'success');
            switchTab('results');
          } else {
            showPageAlert(`ZIP analysis failed: ${data.message || data.error || 'Unknown error.'}`, 'error');
          }
        } catch (err) {
          showPageAlert(err.message || 'Network error during ZIP upload analysis.', 'error');
        } finally {
          analyzerFileInput.value = '';
        }
      } else {
        // Single file upload
        const reader = new FileReader();
        reader.onload = (evt) => {
          analyzerCodeInput.value = evt.target.result;
          updateEditorStats();
          const ext = file.name.split('.').pop().toLowerCase();
          const extLangMap = { js: 'javascript', mjs: 'javascript', cjs: 'javascript', py: 'python', pyw: 'python', ts: 'typescript', tsx: 'typescript', html: 'html', htm: 'html', css: 'css', java: 'java', c: 'c_cpp', h: 'c_cpp', cpp: 'c_cpp', cc: 'c_cpp', cxx: 'c_cpp', hpp: 'c_cpp' };
          if (extLangMap[ext] && analyzerLangSelect) {
            analyzerLangSelect.value = extLangMap[ext];
            analyzerLangSelect.dispatchEvent(new Event('change'));
          }
          if (editorCurrentFilename) editorCurrentFilename.textContent = file.name;
          showPageAlert(`Loaded ${file.name} into editor.`, 'success');
        };
        reader.readAsText(file);
      }
      analyzerFileInput.value = '';
    });
  }

  // AI-powered review and correction assistant (Gemini when configured; static fallback otherwise).
  const btnAiReview = document.getElementById('btnAiReview');
  const aiReviewStatus = document.getElementById('aiReviewStatus');
  const aiReviewOutput = document.getElementById('aiReviewOutput');
  const aiReviewMode = document.getElementById('aiReviewMode');
  const aiReviewSummary = document.getElementById('aiReviewSummary');
  const aiReviewFindings = document.getElementById('aiReviewFindings');
  const aiCorrectedCodeWrap = document.getElementById('aiCorrectedCodeWrap');
  const aiCorrectedCode = document.getElementById('aiCorrectedCode');
  const btnApplyAiCode = document.getElementById('btnApplyAiCode');
  const btnDownloadAiCode = document.getElementById('btnDownloadAiCode');
  let aiCorrectionLanguage = 'javascript';

  if (btnAiReview) {
    btnAiReview.addEventListener('click', async () => {
      const code = analyzerCodeInput ? analyzerCodeInput.value : '';
      const language = analyzerLangSelect ? analyzerLangSelect.value : 'javascript';
      if (!code.trim()) {
        showPageAlert('Paste source code before requesting an AI review.', 'warning');
        return;
      }
      btnAiReview.disabled = true;
      btnAiReview.textContent = 'Reviewing code...';
      if (aiReviewStatus) { aiReviewStatus.style.display = 'block'; aiReviewStatus.textContent = 'Reviewing your code. This may take a few seconds...'; }
      if (aiReviewOutput) aiReviewOutput.style.display = 'none';
      try {
        const response = await fetch('/api/ai/review', {
          method: 'POST', headers: { 'Content-Type': 'application/json', ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {}) },
          body: JSON.stringify({ code, language })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || 'AI review failed.');
        aiCorrectionLanguage = language;
        if (aiReviewMode) aiReviewMode.textContent = data.mode === 'ai' ? `AI POWERED · ${data.provider || 'AI'}` : 'RULE-BASED FALLBACK';
        if (aiReviewSummary) aiReviewSummary.textContent = data.review || 'Review completed.';
        if (aiReviewFindings) {
          const findings = Array.isArray(data.findings) ? data.findings : [];
          aiReviewFindings.innerHTML = findings.length ? findings.map(f => `<div style="padding:12px; border:1px solid var(--border-color, rgba(128,128,128,.25)); border-radius:10px;"><div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;"><strong>${escapeHtml(f.title || 'Finding')}</strong><span class="badge badge-info">${escapeHtml(String(f.severity || 'info').toUpperCase())} · Line ${Math.max(1, Number(f.line) || 1)}</span></div><p style="font-size:.85rem; color:var(--text-muted); margin:7px 0 0;">${escapeHtml(f.explanation || '')}</p><p style="font-size:.85rem; margin:5px 0 0;"><strong>Recommendation:</strong> ${escapeHtml(f.recommendation || 'Review manually.')}</p></div>`).join('') : '<div class="card table-empty">No findings returned. This does not guarantee the code is error-free.</div>';
        }
        const corrected = typeof data.correctedCode === 'string' && data.correctedCode.length > 0 ? data.correctedCode : (data.repairedCode || code);
        if (aiCorrectedCodeWrap) aiCorrectedCodeWrap.style.display = 'block';
        if (aiCorrectedCode) aiCorrectedCode.value = corrected;
        if (aiReviewOutput) aiReviewOutput.style.display = 'block';
        if (aiReviewStatus) {
          aiReviewStatus.style.display = 'block';
          aiReviewStatus.textContent = data.mode === 'ai'
            ? `Real AI review completed via ${data.provider || 'AI'}. Clean production-ready repaired code is generated below!`
            : (data.setupHint || 'Rule-based review completed. Repaired clean code is ready below.');
        }
        // Also update results diff viewer
        const resultsDiffFixedCode = document.getElementById('resultsDiffFixedCode');
        if (resultsDiffFixedCode) resultsDiffFixedCode.value = corrected;
      } catch (error) {
        if (aiReviewStatus) { aiReviewStatus.style.display = 'block'; aiReviewStatus.textContent = error.message || 'Unable to complete review. Run the normal static analysis or retry.'; }
        showPageAlert(error.message || 'AI review failed.', 'error');
      } finally {
        btnAiReview.disabled = false;
        btnAiReview.innerHTML = '<span>Review &amp; Suggest Corrections</span>';
      }
    });
  }

  if (btnApplyAiCode) {
    btnApplyAiCode.addEventListener('click', () => {
      const proposed = aiCorrectedCode ? aiCorrectedCode.value : '';
      if (!proposed.trim()) { showPageAlert('There is no corrected code to apply.', 'warning'); return; }
      recordSnapshot('Before applying AI-proposed correction');
      analyzerCodeInput.value = proposed;
      if (analyzerLangSelect) analyzerLangSelect.value = aiCorrectionLanguage;
      persistWorkingDraft();
      updateEditorStats();
      showPageAlert('✨ Repaired code applied to the editor! Re-analyzing to verify clean status...', 'success');
      if (btnRunAnalysis) btnRunAnalysis.click();
    });
  }

  const btnCopyAiCode = document.getElementById('btnCopyAiCode');
  if (btnCopyAiCode) {
    btnCopyAiCode.addEventListener('click', () => {
      const text = aiCorrectedCode ? aiCorrectedCode.value : '';
      if (!text) return;
      navigator.clipboard.writeText(text).then(() => {
        btnCopyAiCode.innerHTML = '<span>✓ Copied!</span>';
        btnCopyAiCode.classList.add('copied');
        showPageAlert('Repaired code copied to clipboard!', 'success');
        setTimeout(() => {
          btnCopyAiCode.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span>Copy Fixed Code</span>';
          btnCopyAiCode.classList.remove('copied');
        }, 2000);
      }).catch(() => {
        showPageAlert('Failed to copy to clipboard.', 'warning');
      });
    });
  }

  if (btnDownloadAiCode) {
    btnDownloadAiCode.addEventListener('click', () => {
      const code = aiCorrectedCode ? aiCorrectedCode.value : '';
      if (!code) return;
      const extByLanguage = { javascript: 'js', typescript: 'ts', python: 'py', java: 'java', c_cpp: 'c', html: 'html', css: 'css' };
      const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `codeinsight-repaired.${extByLanguage[aiCorrectionLanguage] || 'txt'}`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      showPageAlert('Downloaded repaired code file!', 'success');
    });
  }

  // ==========================================================================
  // CODE FORMATTER & HELPERS
  // ==========================================================================
  function copyToClipboardWithFeedback(text, buttonEl, defaultHtml = '<span>Copy Code</span>') {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      if (buttonEl) {
        buttonEl.innerHTML = '<span>✓ Copied!</span>';
        buttonEl.classList.add('copied');
        setTimeout(() => {
          buttonEl.innerHTML = defaultHtml;
          buttonEl.classList.remove('copied');
        }, 2200);
      }
      showPageAlert('Code copied to clipboard!', 'success');
    }).catch(() => {
      showPageAlert('Failed to copy to clipboard.', 'warning');
    });
  }

  function downloadCodeFile(code, language, prefix = 'codeinsight-fixed') {
    if (!code) return;
    const extMap = { javascript: 'js', typescript: 'ts', python: 'py', java: 'java', c_cpp: 'cpp', html: 'html', css: 'css' };
    const ext = extMap[language] || 'txt';
    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${prefix}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showPageAlert(`Downloaded ${a.download}!`, 'success');
  }

  function formatCodeString(code, lang) {
    if (!code) return '';
    const lines = code.split('\n');
    if (lang === 'python') {
      return lines.map(l => l.trimEnd()).join('\n');
    }
    const indentStr = '    ';
    let indentLevel = 0;
    const formatted = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) {
        formatted.push('');
        continue;
      }
      if (/^[\}\]\)]/.test(line)) {
        indentLevel = Math.max(0, indentLevel - 1);
      }
      formatted.push(indentStr.repeat(indentLevel) + line);
      const openMatches = (line.match(/[\{\[\(]/g) || []).length;
      const closeMatches = (line.match(/[\}\]\)]/g) || []).length;
      const delta = openMatches - closeMatches;
      if (!/^[\}\]\)]/.test(line)) {
        indentLevel = Math.max(0, indentLevel + delta);
      }
    }
    return formatted.join('\n');
  }

  const btnFormatCode = document.getElementById('btnFormatCode');
  if (btnFormatCode) {
    btnFormatCode.addEventListener('click', () => {
      const raw = analyzerCodeInput ? analyzerCodeInput.value : '';
      if (!raw || !raw.trim()) {
        showPageAlert('No code to format in the editor.', 'warning');
        return;
      }
      const lang = analyzerLangSelect ? analyzerLangSelect.value : 'javascript';
      const formatted = formatCodeString(raw, lang);
      if (formatted !== raw) {
        recordSnapshot('Prettified code formatting');
        analyzerCodeInput.value = formatted;
        persistWorkingDraft();
        updateEditorStats();
        showPageAlert('✨ Code formatted and re-indented!', 'success');
      } else {
        showPageAlert('Code indentation is already clean.', 'info');
      }
    });
  }

  // ==========================================================================
  // RESULTS VIEW MODE SELECTOR
  // ==========================================================================
  function setResultsViewMode(mode = 'repaired') {
    const tabRepaired = document.getElementById('btnModeRepairedCode');
    const tabDiagnostics = document.getElementById('btnModeDiagnostics');
    const tabDiff = document.getElementById('btnModeDiff');

    const panelRepaired = document.getElementById('resultsViewRepaired');
    const panelDiagnostics = document.getElementById('resultsViewDiagnostics');
    const panelDiff = document.getElementById('resultsViewDiff');

    if (tabRepaired) tabRepaired.classList.toggle('active', mode === 'repaired');
    if (tabDiagnostics) tabDiagnostics.classList.toggle('active', mode === 'diagnostics');
    if (tabDiff) tabDiff.classList.toggle('active', mode === 'diff');

    if (panelRepaired) panelRepaired.classList.toggle('active', mode === 'repaired');
    if (panelDiagnostics) panelDiagnostics.classList.toggle('active', mode === 'diagnostics');
    if (panelDiff) panelDiff.classList.toggle('active', mode === 'diff');
  }

  const btnModeRepairedCode = document.getElementById('btnModeRepairedCode');
  const btnModeDiagnostics = document.getElementById('btnModeDiagnostics');
  const btnModeDiff = document.getElementById('btnModeDiff');
  if (btnModeRepairedCode) btnModeRepairedCode.addEventListener('click', () => setResultsViewMode('repaired'));
  if (btnModeDiagnostics) btnModeDiagnostics.addEventListener('click', () => setResultsViewMode('diagnostics'));
  if (btnModeDiff) btnModeDiff.addEventListener('click', () => setResultsViewMode('diff'));

  // Run Analysis Action (Standard Static Scan + High-Precision Clean Repair)
  if (btnRunAnalysis) {
    btnRunAnalysis.addEventListener('click', async () => {
      const code = analyzerCodeInput.value;
      if (!code || code.trim().length === 0) {
        showPageAlert('Please enter or paste source code before analyzing.', 'warning');
        return;
      }

      const language = analyzerLangSelect ? analyzerLangSelect.value : 'javascript';
      analyzerStatusPill.textContent = 'Analyzing...';
      analyzerStatusPill.className = 'badge badge-warning';
      btnRunAnalysis.disabled = true;

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
          },
          body: JSON.stringify({ code, language })
        });
        const data = await res.json();

        if (data.success) {
          renderAnalysisReport(data);
          analyzerStatusPill.textContent = `Score: ${data.score}`;
          analyzerStatusPill.className = data.score >= 80 ? 'badge badge-success' : (data.score >= 50 ? 'badge badge-warning' : 'badge badge-danger');
          const issueMsg = (data.findings && data.findings.length > 0)
            ? `${data.findings.length} issue(s) identified.`
            : 'Zero issues detected!';
          showPageAlert(`Analysis completed! Health score: ${data.score}/100. ${issueMsg}`, data.score >= 80 ? 'success' : 'warning');
          switchTab('results');
        } else {
          analyzerStatusPill.textContent = 'Error';
          analyzerStatusPill.className = 'badge badge-danger';
          showPageAlert(data.error || 'Analysis failed.', 'error');
        }
      } catch (err) {
        analyzerStatusPill.textContent = 'Failed';
        analyzerStatusPill.className = 'badge badge-danger';
        showPageAlert('Server connection failed during analysis.', 'error');
      } finally {
        btnRunAnalysis.disabled = false;
      }
    });
  }

  // AI Auto-Fix & Analyze Action (Full AI Review + Complete Production-Ready Repaired Code)
  const btnAiAutoFix = document.getElementById('btnAiAutoFix');
  if (btnAiAutoFix) {
    btnAiAutoFix.addEventListener('click', async () => {
      const code = analyzerCodeInput.value;
      if (!code || code.trim().length === 0) {
        showPageAlert('Please enter or paste source code before analyzing.', 'warning');
        return;
      }

      const language = analyzerLangSelect ? analyzerLangSelect.value : 'javascript';
      analyzerStatusPill.textContent = 'AI Analyzing & Repairing...';
      analyzerStatusPill.className = 'badge badge-warning';
      btnAiAutoFix.disabled = true;
      if (btnRunAnalysis) btnRunAnalysis.disabled = true;

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
          },
          body: JSON.stringify({ code, language, aiAutoRepair: true })
        });
        const data = await res.json();

        if (data.success) {
          renderAnalysisReport(data);
          setResultsViewMode('repaired');
          analyzerStatusPill.textContent = `Score: ${data.score}`;
          analyzerStatusPill.className = data.score >= 80 ? 'badge badge-success' : (data.score >= 50 ? 'badge badge-warning' : 'badge badge-danger');
          showPageAlert(`✨ AI Review & Auto-Repair completed! Health score: ${data.score}/100. Clean working code is ready below.`, data.score >= 80 ? 'success' : 'warning');
          switchTab('results');
        } else {
          analyzerStatusPill.textContent = 'Error';
          analyzerStatusPill.className = 'badge badge-danger';
          showPageAlert(data.error || 'AI analysis failed.', 'error');
        }
      } catch (err) {
        analyzerStatusPill.textContent = 'Failed';
        analyzerStatusPill.className = 'badge badge-danger';
        showPageAlert('Server connection failed during AI analysis.', 'error');
      } finally {
        btnAiAutoFix.disabled = false;
        if (btnRunAnalysis) btnRunAnalysis.disabled = false;
      }
    });
  }

  // ==========================================================================
  // 7. ANALYSIS RESULTS & WORKBENCH RENDERING
  // ==========================================================================
  function renderAnalysisReport(report) {
    currentReport = report;
    selectedFindingIndex = -1;

    // Header Metrics
    const score = typeof report.score === 'number' ? report.score : (Number(report.score) || 0);

    // Extract short letter grade cleanly (e.g. 'A+', 'A', 'B', 'C', 'F')
    let shortGrade = report.shortGrade;
    if (!shortGrade && report.grade) {
      const match = String(report.grade).trim().match(/^(A\+|[A-F])/i);
      shortGrade = match ? match[1].toUpperCase() : String(report.grade).split(' ')[0];
    }
    if (!shortGrade || shortGrade === '--') {
      shortGrade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'F';
    }

    if (resultsScoreVal) resultsScoreVal.textContent = score;
    if (resultsGradeVal) {
      resultsGradeVal.textContent = `GRADE ${shortGrade}`;
    }

    const resultsScoreCircle = document.getElementById('resultsScoreCircle');
    if (resultsScoreCircle) {
      resultsScoreCircle.setAttribute('title', `Code Health: ${score}/100 • Grade: ${shortGrade} (${report.grade || 'Healthy'})`);

      // Dynamic grade-based color styling
      let themeColor = '#10B981';
      let bgGradient = 'rgba(16, 185, 129, 0.14)';
      let glowColor = 'rgba(16, 185, 129, 0.28)';

      if (score >= 90) {
        themeColor = '#10B981';
        bgGradient = 'rgba(16, 185, 129, 0.14)';
        glowColor = 'rgba(16, 185, 129, 0.28)';
      } else if (score >= 80) {
        themeColor = '#3B82F6';
        bgGradient = 'rgba(59, 130, 246, 0.14)';
        glowColor = 'rgba(59, 130, 246, 0.28)';
      } else if (score >= 70) {
        themeColor = '#06B6D4';
        bgGradient = 'rgba(6, 182, 212, 0.14)';
        glowColor = 'rgba(6, 182, 212, 0.28)';
      } else if (score >= 50) {
        themeColor = '#F59E0B';
        bgGradient = 'rgba(245, 158, 11, 0.14)';
        glowColor = 'rgba(245, 158, 11, 0.28)';
      } else {
        themeColor = '#EF4444';
        bgGradient = 'rgba(239, 68, 68, 0.14)';
        glowColor = 'rgba(239, 68, 68, 0.28)';
      }

      resultsScoreCircle.style.borderColor = themeColor;
      resultsScoreCircle.style.background = `radial-gradient(circle, ${bgGradient} 0%, rgba(15, 23, 42, 0.3) 100%)`;
      resultsScoreCircle.style.boxShadow = `0 0 18px ${glowColor}`;
      if (resultsGradeVal) resultsGradeVal.style.color = themeColor;
    }

    if (resultsStatusTitle) {
      resultsStatusTitle.textContent = `Code Health: ${report.grade || (shortGrade + ' Quality')} (${score}/100)`;
    }
    if (resultsStatusSubtitle) {
      resultsStatusSubtitle.textContent = `Analyzed ${(report.language || 'code').toUpperCase()} • ${report.summary || 'Scan complete'}`;
    }

    const counts = {
      error: 0,
      warning: 0,
      quality: 0,
      security: 0
    };

    const findings = report.findings || [];
    findings.forEach(f => {
      const type = (f.type || 'quality').toLowerCase();
      if (counts[type] !== undefined) counts[type]++;
      if (f.isSecurity || f.severity === 'critical') counts.security++;
    });

    if (resultsCountErrors) resultsCountErrors.textContent = counts.error;
    if (resultsCountWarnings) resultsCountWarnings.textContent = counts.warning;
    if (resultsCountQuality) resultsCountQuality.textContent = counts.quality;
    if (resultsCountSecurity) resultsCountSecurity.textContent = counts.security;

    if (filterAllCount) filterAllCount.textContent = findings.length;
    if (filterErrorCount) filterErrorCount.textContent = counts.error;
    if (filterWarningCount) filterWarningCount.textContent = counts.warning;
    if (filterQualityCount) filterQualityCount.textContent = counts.quality;
    if (filterSecurityCount) filterSecurityCount.textContent = counts.security;

    const resFindingsCountTab = document.getElementById('resFindingsCountTab');
    if (resFindingsCountTab) resFindingsCountTab.textContent = findings.length;

    // Render Findings List
    renderFindingsList();

    // Render Code Viewer
    renderCodeViewer(report.code || analyzerCodeInput.value, -1);

    // Render Security Scanner view
    renderSecurityScannerView(findings);

    // Render Code Suggestions view
    renderCodeSuggestionsView(findings);

    // ========================================================================
    // REPAIRED CODE & CHANGELOG POPULATION
    // ========================================================================
    const fixedCode = report.correctedCode || report.repairedCode || analyzerCodeInput.value;
    const resultsMainRepairedTextarea = document.getElementById('resultsMainRepairedTextarea');
    if (resultsMainRepairedTextarea) resultsMainRepairedTextarea.value = fixedCode;

    const repairedCodeLangBadge = document.getElementById('repairedCodeLangBadge');
    if (repairedCodeLangBadge) repairedCodeLangBadge.textContent = (report.language || 'javascript').toUpperCase();

    const resultsDiffOrigCode = document.getElementById('resultsDiffOrigCode');
    if (resultsDiffOrigCode) resultsDiffOrigCode.value = report.code || analyzerCodeInput.value;

    const resultsDiffFixedCode = document.getElementById('resultsDiffFixedCode');
    if (resultsDiffFixedCode) resultsDiffFixedCode.value = fixedCode;

    if (aiCorrectedCode) aiCorrectedCode.value = fixedCode;
    if (aiCorrectedCodeWrap) aiCorrectedCodeWrap.style.display = 'block';

    // Render Changelog & Fixes Breakdown Card
    const resultsChangelogList = document.getElementById('resultsChangelogList');
    const changelogScoreBadge = document.getElementById('changelogScoreBadge');
    const expectedScore = report.expectedRepairedScore || 100;
    const gain = Math.max(5, expectedScore - (report.score || 0));

    if (changelogScoreBadge) {
      changelogScoreBadge.textContent = findings.length > 0
        ? `+${gain} pts (Score: ${report.score} ➔ ${expectedScore}/100)`
        : 'Score: 100/100 (Clean)';
    }

    if (resultsChangelogList) {
      let changelogHtml = '';

      if (report.aiReview) {
        changelogHtml += `
          <div style="padding:12px 14px; border-radius:var(--radius-sm); background:linear-gradient(135deg, rgba(124,58,237,0.12), rgba(37,99,235,0.06)); border:1px solid rgba(124,58,237,0.3); margin-bottom:4px;">
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
              <span class="badge badge-info">AI REVIEW SUMMARY</span>
              <span class="font-mono" style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(report.aiProvider || 'Groq AI')}</span>
            </div>
            <div style="font-size:0.86rem; color:var(--text-main); line-height:1.55;">${escapeHtml(report.aiReview)}</div>
          </div>
        `;
      }

      const fixes = report.appliedFixes || (findings || []).filter(f => f.suggestedFix).map(f => ({
        ruleId: f.ruleId,
        title: f.title,
        line: f.line,
        before: f.suggestedFix?.before,
        after: f.suggestedFix?.after,
        explanation: f.suggestedFix?.explanation || f.explanation
      }));

      if (fixes.length > 0) {
        fixes.forEach((fx, i) => {
          changelogHtml += `
            <div class="changelog-item">
              <div class="changelog-icon">✨</div>
              <div class="changelog-content">
                <div class="changelog-header">
                  <span class="changelog-title">${escapeHtml(fx.title || 'Code Improvement')}</span>
                  <div style="display:flex; gap:6px;">
                    <span class="badge badge-info">${escapeHtml(fx.ruleId || 'RULE')}</span>
                    <span class="badge badge-secondary">Line ${fx.line || 1}</span>
                  </div>
                </div>
                <div class="changelog-desc">${escapeHtml(fx.explanation || 'Clean production code refactoring.')}</div>
                ${fx.after ? `
                  <div class="changelog-diff-pill">
                    <span>${escapeHtml(fx.before ? fx.before.slice(0, 40) : '')}</span>
                    <span style="color:var(--text-dim); margin:0 4px;">➔</span>
                    <strong style="color:#34D399;">${escapeHtml(fx.after.slice(0, 45))}</strong>
                  </div>
                ` : ''}
              </div>
            </div>
          `;
        });
      } else {
        changelogHtml += `<div class="card table-empty">No issues detected! Your code adheres to all syntax and quality standards.</div>`;
      }
      resultsChangelogList.innerHTML = changelogHtml;
    }

    // Auto-Fix Banner
    const resultsAutoFixBanner = document.getElementById('resultsAutoFixBanner');
    const resultsScoreGainBadge = document.getElementById('resultsScoreGainBadge');
    const btnApplyAllSuggestions = document.getElementById('btnApplyAllSuggestions');

    if (findings.length > 0 && fixedCode) {
      if (resultsAutoFixBanner) {
        resultsAutoFixBanner.style.display = 'flex';
        if (resultsScoreGainBadge) {
          resultsScoreGainBadge.textContent = `+${gain} pts (Score: ${report.score} ➔ ${expectedScore}/100)`;
        }
      }
      if (btnApplyAllSuggestions) btnApplyAllSuggestions.style.display = 'inline-flex';
      // Default to showing the Repaired Code panel so the user sees the fixed code immediately!
      setResultsViewMode('repaired');
    } else {
      if (resultsAutoFixBanner) resultsAutoFixBanner.style.display = 'none';
      if (btnApplyAllSuggestions) btnApplyAllSuggestions.style.display = 'none';
      setResultsViewMode('diagnostics');
    }
  }

  // ==========================================================================
  // REPAIRED CODE ACTIONS (COPY, DOWNLOAD, APPLY)
  // ==========================================================================
  const btnRepairedMainCopy = document.getElementById('btnRepairedMainCopy');
  if (btnRepairedMainCopy) {
    btnRepairedMainCopy.addEventListener('click', () => {
      const code = (document.getElementById('resultsMainRepairedTextarea')?.value) ||
                   (currentReport?.correctedCode || currentReport?.repairedCode);
      copyToClipboardWithFeedback(code, btnRepairedMainCopy, '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span>Copy Code</span>');
    });
  }

  const btnRepairedMainDownload = document.getElementById('btnRepairedMainDownload');
  if (btnRepairedMainDownload) {
    btnRepairedMainDownload.addEventListener('click', () => {
      const code = (document.getElementById('resultsMainRepairedTextarea')?.value) ||
                   (currentReport?.correctedCode || currentReport?.repairedCode);
      const lang = (currentReport && currentReport.language) || (analyzerLangSelect ? analyzerLangSelect.value : 'javascript');
      downloadCodeFile(code, lang, 'codeinsight-repaired');
    });
  }

  const btnRepairedMainApply = document.getElementById('btnRepairedMainApply');
  if (btnRepairedMainApply) {
    btnRepairedMainApply.addEventListener('click', () => {
      const code = (document.getElementById('resultsMainRepairedTextarea')?.value) ||
                   (currentReport?.correctedCode || currentReport?.repairedCode);
      if (!code || !code.trim()) {
        showPageAlert('No repaired code to apply.', 'warning');
        return;
      }
      recordSnapshot('Applied clean repaired code');
      analyzerCodeInput.value = code;
      persistWorkingDraft();
      updateEditorStats();
      showPageAlert('✨ Repaired code applied to editor! Verifying 100% clean health score...', 'success');
      switchTab('analyzer');
      if (btnRunAnalysis) btnRunAnalysis.click();
    });
  }

  const btnDiffCopyFixed = document.getElementById('btnDiffCopyFixed');
  if (btnDiffCopyFixed) {
    btnDiffCopyFixed.addEventListener('click', () => {
      const code = (document.getElementById('resultsDiffFixedCode')?.value) ||
                   (currentReport?.correctedCode || currentReport?.repairedCode);
      copyToClipboardWithFeedback(code, btnDiffCopyFixed, 'Copy Fixed');
    });
  }

  const btnDiffApplyFixed = document.getElementById('btnDiffApplyFixed');
  if (btnDiffApplyFixed) {
    btnDiffApplyFixed.addEventListener('click', () => {
      const code = (document.getElementById('resultsDiffFixedCode')?.value) ||
                   (currentReport?.correctedCode || currentReport?.repairedCode);
      if (!code || !code.trim()) return;
      recordSnapshot('Applied fixed code from diff');
      analyzerCodeInput.value = code;
      persistWorkingDraft();
      updateEditorStats();
      showPageAlert('✨ Fixed code applied! Re-analyzing...', 'success');
      switchTab('analyzer');
      if (btnRunAnalysis) btnRunAnalysis.click();
    });
  }

  // Auto-Fix & Results Diff Action Listeners
  const btnResultsApplyAutoFix = document.getElementById('btnResultsApplyAutoFix');
  if (btnResultsApplyAutoFix) {
    btnResultsApplyAutoFix.addEventListener('click', () => {
      const fixedCode = (document.getElementById('resultsMainRepairedTextarea')?.value) ||
                        (document.getElementById('resultsDiffFixedCode')?.value) ||
                        (currentReport && (currentReport.correctedCode || currentReport.repairedCode));
      if (!fixedCode || !fixedCode.trim()) {
        showPageAlert('No repaired code available to apply.', 'warning');
        return;
      }
      recordSnapshot('Applied automated code repair');
      analyzerCodeInput.value = fixedCode;
      persistWorkingDraft();
      updateEditorStats();
      showPageAlert('✨ Repaired code applied! Rescanning to verify 100% clean status...', 'success');
      switchTab('analyzer');
      if (btnRunAnalysis) btnRunAnalysis.click();
    });
  }

  const btnResultsCopyFixed = document.getElementById('btnResultsCopyFixed');
  if (btnResultsCopyFixed) {
    btnResultsCopyFixed.addEventListener('click', () => {
      const fixedCode = (document.getElementById('resultsMainRepairedTextarea')?.value) ||
                        (document.getElementById('resultsDiffFixedCode')?.value) ||
                        (currentReport && (currentReport.correctedCode || currentReport.repairedCode));
      copyToClipboardWithFeedback(fixedCode, btnResultsCopyFixed, '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span>Copy Fixed Code</span>');
    });
  }

  const btnResultsToggleDiff = document.getElementById('btnResultsToggleDiff');
  if (btnResultsToggleDiff) {
    btnResultsToggleDiff.addEventListener('click', () => {
      setResultsViewMode('diff');
      const diffPanel = document.getElementById('resultsViewDiff');
      if (diffPanel) diffPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  const btnApplyAllSuggestions = document.getElementById('btnApplyAllSuggestions');
  if (btnApplyAllSuggestions) {
    btnApplyAllSuggestions.addEventListener('click', () => {
      const fixedCode = (document.getElementById('resultsMainRepairedTextarea')?.value) ||
                        (currentReport && (currentReport.correctedCode || currentReport.repairedCode)) ||
                        (aiCorrectedCode && aiCorrectedCode.value);
      if (!fixedCode) {
        showPageAlert('No repaired code available to apply.', 'warning');
        return;
      }
      recordSnapshot('Applied all code suggestions');
      analyzerCodeInput.value = fixedCode;
      persistWorkingDraft();
      updateEditorStats();
      showPageAlert('✨ All suggestions applied! Re-running scan...', 'success');
      switchTab('analyzer');
      if (btnRunAnalysis) btnRunAnalysis.click();
    });
  }

  // Findings filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderFindingsList();
    });
  });

  function renderFindingsList() {
    if (!findingsContainer || !currentReport) return;
    const findings = currentReport.findings || [];

    const filtered = findings.filter(f => {
      if (currentFilter === 'all') return true;
      if (currentFilter === 'security') return f.isSecurity || (f.type === 'security') || f.severity === 'critical';
      return (f.type || 'quality').toLowerCase() === currentFilter;
    });

    if (filtered.length === 0) {
      findingsContainer.innerHTML = '<div class="card table-empty">No findings match the selected filter. Code looks clean!</div>';
      return;
    }

    let html = '';
    filtered.forEach((f, idx) => {
      const origIndex = findings.indexOf(f);
      const isSelected = origIndex === selectedFindingIndex;
      const sevClass = f.severity === 'critical' || f.severity === 'high' ? 'badge-danger' : f.severity === 'medium' ? 'badge-warning' : 'badge-info';

      html += `
        <div class="finding-card ${isSelected ? 'active' : ''}" data-index="${origIndex}">
          <div class="finding-card-header">
            <span class="badge ${sevClass}">${(f.severity || 'info').toUpperCase()}</span>
            <span class="font-mono" style="font-size:0.75rem; color:var(--text-muted);">${f.ruleId || 'RULE'}</span>
            <span class="font-mono" style="font-size:0.75rem; color:var(--text-dim);">Line ${f.line || 1}</span>
          </div>
          <div class="finding-card-title">${escapeHtml(f.title || f.ruleName || 'Diagnostic Finding')}</div>
          <div class="finding-card-snippet">${escapeHtml(f.description || f.impact || '')}</div>
        </div>
      `;
    });

    findingsContainer.innerHTML = html;

    // Attach click listeners
    findingsContainer.querySelectorAll('.finding-card').forEach(card => {
      card.addEventListener('click', () => {
        const idx = parseInt(card.dataset.index, 10);
        selectFinding(idx);
      });
    });

    // Automatically select first finding if none selected
    if (selectedFindingIndex === -1 && filtered.length > 0) {
      selectFinding(findings.indexOf(filtered[0]));
    }
  }

  function selectFinding(idx) {
    if (!currentReport || !currentReport.findings[idx]) return;
    selectedFindingIndex = idx;
    const f = currentReport.findings[idx];

    // Highlight card
    findingsContainer.querySelectorAll('.finding-card').forEach(c => {
      c.classList.toggle('active', parseInt(c.dataset.index, 10) === idx);
    });

    // Populate Right-hand Finding Detail Box
    if (detailBadgeSeverity) {
      detailBadgeSeverity.textContent = (f.severity || 'INFO').toUpperCase();
      detailBadgeSeverity.className = `badge ${f.severity === 'critical' || f.severity === 'high' ? 'badge-danger' : f.severity === 'medium' ? 'badge-warning' : 'badge-info'}`;
    }
    if (detailRuleId) detailRuleId.textContent = f.ruleId || 'DIAGNOSTIC';
    if (detailLocation) {
      const fileLabel = f.fileName || `snippet.${f.language || 'code'}`;
      detailLocation.textContent = `File: ${fileLabel} : Line ${f.line || 1}`;
    }
    if (detailTitle) detailTitle.textContent = f.title || f.ruleName;
    if (detailExplanation) detailExplanation.textContent = f.explanation || f.aiExplanation || f.description;

    if (detailExtraFields) detailExtraFields.style.display = 'flex';
    if (detailWhyItMatters) detailWhyItMatters.textContent = f.whyItMatters || f.impact || 'Improves code readability and runtime safety.';
    if (detailLearningConcept) detailLearningConcept.textContent = f.learningConcept || f.category || 'General Programming Best Practice';

    if (f.suggestedFix) {
      if (detailRemediationBox) detailRemediationBox.style.display = 'block';
      if (detailRemediationText) detailRemediationText.textContent = f.suggestedFix.explanation || f.suggestedFix.after;
      if (btnDetailApplyFix) {
        btnDetailApplyFix.onclick = () => openDiffModal(idx);
      }
    } else {
      if (detailRemediationBox) detailRemediationBox.style.display = 'none';
    }

    // Highlight code line in source viewer
    const findingFile = Array.isArray(currentReport.files)
      ? currentReport.files.find(file => file.name === f.fileName)
      : null;
    renderCodeViewer(findingFile?.content || currentReport.code || analyzerCodeInput.value, f.line || 1, f.severity);
  }

  function renderCodeViewer(code, highlightLine = -1, severity = 'medium') {
    if (!resultsCodeViewer) return;
    const lines = (code || '').split('\n');
    let html = '';

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const isTarget = lineNum === highlightLine;
      const hlClass = isTarget ? (severity === 'critical' || severity === 'high' ? 'line-highlight-err' : 'line-highlight') : '';

      html += `
        <div class="code-viewer-line ${hlClass}" id="codeViewerLine-${lineNum}">
          <span class="code-viewer-num">${lineNum}</span>
          <span class="code-viewer-text">${escapeHtml(lineText) || '&nbsp;'}</span>
        </div>
      `;
    });

    resultsCodeViewer.innerHTML = html;

    // Scroll highlighted line into view
    if (highlightLine > 0) {
      const targetEl = document.getElementById(`codeViewerLine-${highlightLine}`);
      if (targetEl) {
        targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }

  // ==========================================================================
  // 8. SECURITY SCANNER VIEW
  // ==========================================================================
  function renderSecurityScannerView(findings) {
    if (!document.getElementById('securityCardsContainer')) return;
    const container = document.getElementById('securityCardsContainer');
    const secFindings = (findings || []).filter(f => f.isSecurity || f.severity === 'critical' || (f.category && f.category.toLowerCase().includes('security')));

    let critCount = 0;
    let highCount = 0;
    secFindings.forEach(f => {
      if (f.severity === 'critical') critCount++;
      else if (f.severity === 'high') highCount++;
    });

    const critEl = document.getElementById('secCriticalCount');
    if (critEl) critEl.textContent = critCount;
    const highEl = document.getElementById('secHighCount');
    if (highEl) highEl.textContent = highCount;

    if (secFindings.length === 0) {
      container.innerHTML = '<div class="card table-empty" style="grid-column:1/-1;">No security vulnerabilities detected in the current code buffer.</div>';
      return;
    }

    let html = '';
    secFindings.forEach((f, idx) => {
      const sevClass = f.severity === 'critical' ? 'badge-danger' : 'badge-warning';
      html += `
        <div class="security-card ${f.severity}">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="badge ${sevClass}">${f.severity.toUpperCase()}</span>
            <span class="font-mono" style="font-size:0.75rem; color:var(--text-muted);">${f.ruleId}</span>
            <span class="font-mono" style="font-size:0.75rem; color:var(--text-dim);">Line ${f.line}</span>
          </div>
          <h4 style="font-size:1.05rem; font-weight:800; color:var(--text-main);">${escapeHtml(f.title || f.ruleName)}</h4>
          <p style="font-size:0.85rem; color:var(--text-muted); line-height:1.5;">${escapeHtml(f.explanation || f.description)}</p>
          <div style="background:#080D18; padding:10px; border-radius:var(--radius-sm); font-family:var(--font-mono); font-size:0.78rem; color:#FCA5A5;">
            <strong>Target:</strong> Line ${f.line}: ${escapeHtml(f.description)}
          </div>
          <div style="font-size:0.8rem; color:var(--text-dim);">
            <strong>Remediation:</strong> ${escapeHtml(f.whyItMatters || 'Refactor to safe APIs.')}
          </div>
          ${f.suggestedFix ? `
            <button class="btn btn-secondary btn-sm btnSecReviewFix" data-index="${findings.indexOf(f)}" style="margin-top:auto;">
              <span>Review Proposed Fix</span>
            </button>
          ` : ''}
        </div>
      `;
    });

    container.innerHTML = html;

    container.querySelectorAll('.btnSecReviewFix').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.index, 10);
        openDiffModal(idx);
      });
    });
  }

  // ==========================================================================
  // 9. CODE SUGGESTIONS & PROPOSED FIX REMEDIATION
  // ==========================================================================
  function recordSnapshot(desc = 'Code state snapshot') {
    const code = analyzerCodeInput.value;
    undoStack.push({ code, language: analyzerLangSelect ? analyzerLangSelect.value : 'javascript', timestamp: Date.now(), desc });
    if (undoStack.length > 25) undoStack.shift(); // Keep latest 25 snapshots
    updateUndoButton();
  }

  function updateUndoButton() {
    if (!btnUndoFix || !undoStackCount) return;
    undoStackCount.textContent = undoStack.length;
    btnUndoFix.disabled = undoStack.length === 0;
  }

  if (btnUndoFix) {
    btnUndoFix.addEventListener('click', () => {
      if (undoStack.length === 0) return;
      const snapshot = undoStack.pop();
      analyzerCodeInput.value = snapshot.code;
      if (analyzerLangSelect && snapshot.language) {
        analyzerLangSelect.value = snapshot.language;
        analyzerLangSelect.dispatchEvent(new Event('change'));
      }
      persistWorkingDraft();
      updateEditorStats();
      updateUndoButton();
      showPageAlert(`Reverted last change (${snapshot.desc}). Re-scanning...`, 'info');

      // Re-trigger analysis
      if (btnRunAnalysis) btnRunAnalysis.click();
    });
  }

  function renderCodeSuggestionsView(findings) {
    if (!suggestionsContainer) return;
    const fixable = (findings || []).filter(f => f.suggestedFix);

    if (fixable.length === 0) {
      suggestionsContainer.innerHTML = '<div class="card table-empty">No automated suggestions available for the current code buffer.</div>';
      return;
    }

    let html = '';
    fixable.forEach(f => {
      const origIndex = findings.indexOf(f);
      html += `
        <div class="suggestion-card">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
              <span class="badge badge-info">${f.ruleId}</span>
              <span style="font-size:0.85rem; font-weight:700; margin-left:8px;">${escapeHtml(f.title || f.ruleName)}</span>
            </div>
            <span class="font-mono" style="font-size:0.8rem; color:var(--text-dim);">Line ${f.line}</span>
          </div>

          <p style="font-size:0.85rem; color:var(--text-muted);">${escapeHtml(f.suggestedFix.explanation || f.explanation)}</p>

          <div class="suggestion-diff-preview">
            <div>
              <div style="font-size:0.7rem; font-weight:800; color:#F87171; margin-bottom:4px;">BEFORE</div>
              <pre style="white-space:pre-wrap; color:var(--text-muted);">${escapeHtml(f.suggestedFix.before)}</pre>
            </div>
            <div>
              <div style="font-size:0.7rem; font-weight:800; color:#34D399; margin-bottom:4px;">AFTER</div>
              <pre style="white-space:pre-wrap; color:var(--text-main);">${escapeHtml(f.suggestedFix.after)}</pre>
            </div>
          </div>

          <div style="display:flex; justify-content:flex-end;">
            <button class="btn btn-primary btn-sm btnOpenDiff" data-index="${origIndex}">
              <span>Preview Diff &amp; Apply</span>
            </button>
          </div>
        </div>
      `;
    });

    suggestionsContainer.innerHTML = html;

    suggestionsContainer.querySelectorAll('.btnOpenDiff').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.index, 10);
        openDiffModal(idx);
      });
    });
  }

  // Diff Preview Modal
  function openDiffModal(findingIndex) {
    if (!currentReport || !currentReport.findings[findingIndex]) return;
    const f = currentReport.findings[findingIndex];
    if (!f.suggestedFix) return;

    activeProposedFix = {
      findingIndex,
      before: f.suggestedFix.before,
      after: f.suggestedFix.after,
      line: f.line,
      ruleId: f.ruleId
    };

    if (diffFindingRule) diffFindingRule.textContent = `Rule ${f.ruleId} (Line ${f.line}): ${f.title}`;
    if (diffBeforeCode) diffBeforeCode.textContent = f.suggestedFix.before;
    if (diffAfterCode) diffAfterCode.textContent = f.suggestedFix.after;

    if (diffPreviewModal) diffPreviewModal.style.display = 'flex';
  }

  function closeDiffModal() {
    if (diffPreviewModal) diffPreviewModal.style.display = 'none';
    activeProposedFix = null;
  }

  if (btnCloseDiffModal) btnCloseDiffModal.addEventListener('click', closeDiffModal);
  if (btnCancelDiff) btnCancelDiff.addEventListener('click', closeDiffModal);

  // Confirm & Apply Fix Workflow (Pre-Verification, Post-Validation, Rollback on failure)
  if (btnConfirmApplyFix) {
    btnConfirmApplyFix.addEventListener('click', async () => {
      if (!activeProposedFix) return;
      const fix = activeProposedFix;
      closeDiffModal();

      // 1. Record snapshot for undo
      recordSnapshot(`Before applying ${fix.ruleId} fix`);

      const currentCode = analyzerCodeInput.value;
      let updatedCode = currentCode;

      // Prefer exact replacement of the full snippet; this preserves all
      // untouched lines and supports fixes that span multiple lines.
      if (typeof fix.before === 'string' && fix.before.length > 0 && currentCode.includes(fix.before)) {
        updatedCode = currentCode.replace(fix.before, fix.after);
      } else {
        // Fallback to the reported line only when the source still matches.
        const lines = currentCode.split('\n');
        const targetLineIdx = Number(fix.line) - 1;
        const beforeText = String(fix.before || '').trim();
        const currentLine = lines[targetLineIdx] || '';

        if (
          targetLineIdx >= 0 &&
          currentLine &&
          beforeText &&
          (currentLine.includes(beforeText) || beforeText.includes(currentLine.trim()))
        ) {
          lines[targetLineIdx] = fix.after;
          updatedCode = lines.join('\n');
        } else {
          showPageAlert('Source code at the specified location no longer matches this fix. Re-analyze the current code and try again.', 'warning');
          return;
        }
      }

      if (updatedCode === currentCode) {
        showPageAlert('This fix did not change the source code. No changes were applied.', 'warning');
        return;
      }

      analyzerCodeInput.value = updatedCode;
      // Persist the current working copy so navigation/reload does not
      // silently restore the previous snippet.
      try {
        localStorage.setItem('codeinsight_working_code', updatedCode);
        localStorage.setItem('codeinsight_working_language', analyzerLangSelect ? analyzerLangSelect.value : 'javascript');
      } catch (storageError) {
        console.warn('Could not persist working code in local storage.', storageError);
      }
      updateEditorStats();

      // 3. Post-Fix Validation Rescan
      showPageAlert('Proposed fix applied. Performing automated validation rescan...', 'info');
      const lang = analyzerLangSelect ? analyzerLangSelect.value : 'javascript';

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
          },
          body: JSON.stringify({ code: analyzerCodeInput.value, language: lang })
        });
        const data = await res.json();

        if (data.success) {
          renderAnalysisReport(data);
          const remaining = Array.isArray(data.findings) ? data.findings.length : 0;
          showPageAlert(`Re-analysis complete: Code Health ${data.score}/100. ${remaining} finding(s) remain.`, 'success');
          switchTab('results');
        } else {
          // Syntax/Validation failure! Prompt rollback
          showPageAlert(`Validation failed after fix: ${data.error}. Reverting to previous state...`, 'error');
          if (btnUndoFix) btnUndoFix.click();
        }
      } catch (e) {
        // Keep editor, score and report consistent: restore the pre-fix snapshot
        // when the validation request cannot confirm the result.
        showPageAlert('Validation rescan failed. Restoring the previous source; please check the backend and try again.', 'error');
        if (btnUndoFix) btnUndoFix.click();
      }
    });
  }

  // Quick jump from results to suggestions tab
  if (btnResultsGoSuggestions) {
    btnResultsGoSuggestions.addEventListener('click', () => switchTab('suggestions'));
  }

  // Export Report (Markdown)
  if (btnExportMarkdown) {
    btnExportMarkdown.addEventListener('click', async () => {
      const code = analyzerCodeInput.value;
      const language = analyzerLangSelect ? analyzerLangSelect.value : 'javascript';
      if (!code) {
        showPageAlert('No code to export.', 'warning');
        return;
      }

      try {
        const res = await fetch('/api/export/report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
          },
          body: JSON.stringify({ code, language, format: 'markdown' })
        });
        if (!res.ok) {
          const errorData = await res.json().catch(() => ({}));
          throw new Error(errorData.message || 'The report could not be exported.');
        }
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `codeinsight-report-${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        showPageAlert('Exported Markdown inspection report!', 'success');
      } catch (err) {
        showPageAlert('Failed to export report.', 'error');
      }
    });
  }

  // CSV export must use fetch because bearer tokens in localStorage are not sent by window.open().
  async function downloadCsvExport() {
    if (!authToken) {
      showPageAlert('Please sign in before exporting analysis history.', 'warning');
      return;
    }
    try {
      const res = await fetch('/api/export/csv', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.message || 'CSV export failed.');
      }
      const blob = await res.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = `CodeInsight-Analysis-Export-${Date.now()}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 1000);
      showPageAlert('CSV export downloaded successfully.', 'success');
    } catch (error) {
      showPageAlert(error.message || 'Failed to export CSV.', 'error');
    }
  }

  if (btnExportCsv) btnExportCsv.addEventListener('click', downloadCsvExport);

  // ==========================================================================
  // 10. LANGUAGE SUPPORT CATALOG VIEW
  // ==========================================================================
  async function loadLanguagesCatalog() {
    const grid = document.getElementById('languagesCatalogGrid');
    if (!grid) return;

    try {
      const res = await fetch('/api/languages');
      const data = await res.json();
      if (data.success && data.languages) {
        let html = '';
        data.languages.forEach(lang => {
          const badgeClass = lang.supportLevel === 'Full' ? 'badge-success' : 'badge-warning';
          html += `
            <div class="lang-card">
              <div class="lang-card-header">
                <span class="lang-card-title">${lang.name}</span>
                <span class="badge ${badgeClass}">${lang.supportLevel} Support</span>
              </div>
              <div style="font-size:0.8rem; color:var(--text-dim);">
                Engine: <strong style="color:var(--text-main);">${escapeHtml(lang.engineType || lang.analysisType || 'Static Analysis')}</strong> • ${lang.rulesCount} Rules
              </div>
              <div>
                <strong style="font-size:0.75rem; color:var(--text-muted); display:block; margin-bottom:4px;">CHECKS PERFORMED:</strong>
                <ul style="font-size:0.8rem; color:var(--text-dim); line-height:1.6; margin-left:16px;">
                  ${lang.checks.slice(0, 5).map(c => `<li>${escapeHtml(c)}</li>`).join('')}
                </ul>
              </div>
              <div style="background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.2); padding:10px; border-radius:var(--radius-sm); font-size:0.75rem; color:#FCD34D;">
                <strong>Limitations:</strong> ${escapeHtml(lang.limitations)}
              </div>
            </div>
          `;
        });
        grid.innerHTML = html;
      }
    } catch (e) {
      grid.innerHTML = '<div class="card table-empty">Error loading language capabilities catalog.</div>';
    }
  }

  // ==========================================================================
  // 11. ANALYSIS HISTORY VIEW
  // ==========================================================================
  async function loadUserHistory() {
    const tbody = document.getElementById('userHistoryTbody');
    if (!tbody) return;

    if (!authToken) {
      tbody.innerHTML = '<tr><td colspan="7" class="table-empty">Please sign in to persist and view personal analysis history.</td></tr>';
      return;
    }

    try {
      const res = await fetch('/api/user/history', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.history) {
        if (data.history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No history recorded yet. Run your first analysis in the Code Analyzer!</td></tr>';
          return;
        }

        let html = '';
        data.history.forEach(item => {
          const dateStr = new Date(item.timestamp).toLocaleString();
          const scoreClass = item.healthScore >= 90 ? 'badge-success' : item.healthScore >= 70 ? 'badge-warning' : 'badge-danger';
          html += `
            <tr>
              <td>${dateStr}</td>
              <td><span class="font-mono">${(item.language || 'code').toUpperCase()}</span></td>
              <td><span class="badge ${scoreClass}">${item.healthScore}/100</span></td>
              <td style="color:var(--danger);">${item.errorsCount || 0}</td>
              <td style="color:var(--warning);">${item.warningsCount || 0}</td>
              <td style="color:var(--purple-accent);">${item.securityCount || 0}</td>
              <td>
                <button class="btn btn-secondary btn-sm btnReopenHistory" data-id="${item.scanId || item.id}">
                  <span>Reopen</span>
                </button>
              </td>
            </tr>
          `;
        });
        tbody.innerHTML = html;

        tbody.querySelectorAll('.btnReopenHistory').forEach(btn => {
          btn.addEventListener('click', () => reopenScanHistoryItem(btn.dataset.id));
        });
      }
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="7" class="table-empty">Error retrieving history records.</td></tr>';
    }
  }

  async function reopenScanHistoryItem(scanId) {
    try {
      const res = await fetch(`/api/user/history/${scanId}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.scan) {
        analyzerCodeInput.value = data.scan.codeSnippet || '';
        updateEditorStats();
        if (analyzerLangSelect) {
          analyzerLangSelect.value = data.scan.language;
          analyzerLangSelect.dispatchEvent(new Event('change'));
        }
        renderAnalysisReport({
          success: true,
          language: data.scan.language,
          score: data.scan.healthScore,
          grade: data.scan.healthScore >= 90 ? 'A+' : data.scan.healthScore >= 80 ? 'A' : data.scan.healthScore >= 70 ? 'B' : 'C',
          findings: data.scan.findings || [],
          code: data.scan.codeSnippet,
          summary: data.scan.summary
        });
        showPageAlert('Analysis history record reopened in workspace!', 'success');
        switchTab('results');
      }
    } catch (e) {
      showPageAlert('Unable to load analysis record.', 'error');
    }
  }

  const btnClearHistoryBtn = document.getElementById('btnClearHistoryBtn');
  if (btnClearHistoryBtn) {
    btnClearHistoryBtn.addEventListener('click', async () => {
      if (!confirm('Are you sure you want to clear your entire personal analysis history?')) return;
      try {
        const res = await fetch('/api/user/history', {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.success) {
          showPageAlert('History cleared successfully.', 'info');
          loadUserHistory();
          loadUserDashboardMetrics();
        }
      } catch (e) {
        showPageAlert('Error clearing history.', 'error');
      }
    });
  }

  // ==========================================================================
  // 12. USER DASHBOARD METRICS
  // ==========================================================================
  async function loadUserDashboardMetrics() {
    if (!authToken) {
      const tbody = document.getElementById('dashRecentHistoryTbody');
      if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Sign in to view personal code analytics and recent records.</td></tr>';
      return;
    }

    try {
      const res = await fetch('/api/user/history', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.history) {
        const history = data.history;
        const total = history.length;
        let sumScore = 0;
        let totalErrors = 0;
        let totalWarnings = 0;
        let totalSecurity = 0;

        history.forEach(h => {
          sumScore += (h.healthScore || 0);
          totalErrors += (h.errorsCount || 0);
          totalWarnings += (h.warningsCount || 0);
          totalSecurity += (h.securityCount || 0);
        });

        const avgScore = total > 0 ? Math.round(sumScore / total) : '--';

        const dashTotalScans = document.getElementById('dashTotalScans');
        if (dashTotalScans) dashTotalScans.textContent = total;
        const dashAvgHealth = document.getElementById('dashAvgHealth');
        if (dashAvgHealth) dashAvgHealth.textContent = avgScore !== '--' ? `${avgScore}/100` : '--';
        const dashTotalErrors = document.getElementById('dashTotalErrors');
        if (dashTotalErrors) dashTotalErrors.textContent = totalErrors;
        const dashTotalWarnings = document.getElementById('dashTotalWarnings');
        if (dashTotalWarnings) dashTotalWarnings.textContent = totalWarnings;
        const dashTotalSecurity = document.getElementById('dashTotalSecurity');
        if (dashTotalSecurity) dashTotalSecurity.textContent = totalSecurity;

        // Recent 5 table
        const tbody = document.getElementById('dashRecentHistoryTbody');
        if (tbody) {
          if (history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No analysis records found. Run your first analysis above!</td></tr>';
          } else {
            let html = '';
            history.slice(0, 5).forEach(item => {
              const dateStr = new Date(item.timestamp).toLocaleString();
              const scoreClass = item.healthScore >= 90 ? 'badge-success' : item.healthScore >= 70 ? 'badge-warning' : 'badge-danger';
              html += `
                <tr>
                  <td>${dateStr}</td>
                  <td><span class="font-mono">${(item.language || 'code').toUpperCase()}</span></td>
                  <td><span class="badge ${scoreClass}">${item.healthScore}/100</span></td>
                  <td>${item.errorsCount || 0} err / ${item.warningsCount || 0} warn</td>
                  <td>
                    <button class="btn btn-ghost btn-sm btnDashReopen" data-id="${item.scanId || item.id}">Open</button>
                  </td>
                </tr>
              `;
            });
            tbody.innerHTML = html;

            tbody.querySelectorAll('.btnDashReopen').forEach(btn => {
              btn.addEventListener('click', () => reopenScanHistoryItem(btn.dataset.id));
            });
          }
        }
      }
    } catch (e) {}
  }

  // ==========================================================================
  // 13. USER PROFILE & USER SETTINGS
  // ==========================================================================
  function populateUserProfileView() {
    if (!currentUser) return;
    const profNameDisplay = document.getElementById('profNameDisplay');
    const profEmailDisplay = document.getElementById('profEmailDisplay');
    const profRoleBadge = document.getElementById('profRoleBadge');
    const profAvatarDisplay = document.getElementById('profAvatarDisplay');
    const profUserId = document.getElementById('profUserId');
    const profCreatedDate = document.getElementById('profCreatedDate');

    if (profNameDisplay) profNameDisplay.textContent = currentUser.name || currentUser.username;
    if (profEmailDisplay) profEmailDisplay.textContent = currentUser.email || 'user@codeinsight.local';
    if (profRoleBadge) {
      profRoleBadge.textContent = currentUser.role.toUpperCase();
      profRoleBadge.className = `role-pill role-${currentUser.role}`;
    }
    if (profAvatarDisplay) {
      profAvatarDisplay.textContent = (currentUser.avatar || currentUser.name || currentUser.username || 'U').slice(0, 2).toUpperCase();
    }
    if (profUserId) profUserId.textContent = currentUser.id || currentUser._id || 'USR-01';
    if (profCreatedDate) profCreatedDate.textContent = currentUser.createdAt ? new Date(currentUser.createdAt).toLocaleDateString() : 'Active';

    const editName = document.getElementById('profEditName');
    if (editName) editName.value = currentUser.name || '';
    const editAvatar = document.getElementById('profEditAvatar');
    if (editAvatar) editAvatar.value = currentUser.avatar || '';
    const editBio = document.getElementById('profEditBio');
    if (editBio) editBio.value = currentUser.bio || '';
  }

  const formEditProfile = document.getElementById('formEditProfile');
  const profFeedback = document.getElementById('profFeedback');
  if (formEditProfile) {
    formEditProfile.addEventListener('submit', async (e) => {
      e.preventDefault();
      profFeedback.style.display = 'none';

      const name = document.getElementById('profEditName').value.trim();
      const avatar = document.getElementById('profEditAvatar').value.trim();
      const bio = document.getElementById('profEditBio').value.trim();

      try {
        const res = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ name, avatar, bio })
        });
        const data = await res.json();
        if (data.success && data.user) {
          currentUser = data.user;
          applyLoggedInUI();
          populateUserProfileView();
          profFeedback.textContent = 'Profile successfully updated!';
          profFeedback.className = 'feedback-msg success';
          profFeedback.style.display = 'block';
        } else {
          profFeedback.textContent = data.error || 'Failed to update profile.';
          profFeedback.className = 'feedback-msg error';
          profFeedback.style.display = 'block';
        }
      } catch (err) {
        profFeedback.textContent = 'Error updating profile.';
        profFeedback.className = 'feedback-msg error';
        profFeedback.style.display = 'block';
      }
    });
  }

  function populateUserSettingsView() {
    if (!currentUser) return;
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const setTheme = document.getElementById('setTheme');
    if (setTheme) setTheme.value = currentTheme;

    const userSettings = currentUser.settings || {};
    const setDefaultLang = document.getElementById('setDefaultLang');
    if (setDefaultLang && userSettings.defaultLanguage) setDefaultLang.value = userSettings.defaultLanguage;
    const setAutoDetect = document.getElementById('setAutoDetect');
    if (setAutoDetect) setAutoDetect.checked = userSettings.autoDetect ?? userSettings.autoDetectLanguage ?? true;
  }

  const formUserSettings = document.getElementById('formUserSettings');
  const settingsFeedback = document.getElementById('settingsFeedback');
  if (formUserSettings) {
    formUserSettings.addEventListener('submit', async (e) => {
      e.preventDefault();
      settingsFeedback.style.display = 'none';

      const theme = document.getElementById('setTheme').value;
      const defaultLanguage = document.getElementById('setDefaultLang').value;
      const autoDetect = document.getElementById('setAutoDetect').checked;

      // Apply theme immediately
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('codeinsight-theme', theme);

      try {
        const res = await fetch('/api/user/settings', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ theme, defaultLanguage, autoDetect })
        });
        const data = await res.json();
        if (data.success) {
          if (currentUser) currentUser.settings = data.settings;
          settingsFeedback.textContent = 'Preferences successfully saved!';
          settingsFeedback.className = 'feedback-msg success';
          settingsFeedback.style.display = 'block';
        } else {
          settingsFeedback.textContent = data.error || 'Error saving settings.';
          settingsFeedback.className = 'feedback-msg error';
          settingsFeedback.style.display = 'block';
        }
      } catch (err) {
        settingsFeedback.textContent = 'Network error saving preferences.';
        settingsFeedback.className = 'feedback-msg error';
        settingsFeedback.style.display = 'block';
      }
    });
  }

  // Change Password Form
  const formChangePassword = document.getElementById('formChangePassword');
  const pwdFeedback = document.getElementById('pwdFeedback');
  if (formChangePassword) {
    formChangePassword.addEventListener('submit', async (e) => {
      e.preventDefault();
      pwdFeedback.style.display = 'none';

      const currentPassword = document.getElementById('pwdCurrent').value;
      const newPassword = document.getElementById('pwdNew').value;
      const confirmPassword = document.getElementById('pwdConfirm').value;

      if (newPassword !== confirmPassword) {
        pwdFeedback.textContent = 'New passwords do not match.';
        pwdFeedback.className = 'feedback-msg error';
        pwdFeedback.style.display = 'block';
        return;
      }

      try {
        const res = await fetch('/api/user/change-password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ currentPassword, newPassword })
        });
        const data = await res.json();
        if (data.success) {
          formChangePassword.reset();
          pwdFeedback.textContent = 'Password updated successfully!';
          pwdFeedback.className = 'feedback-msg success';
          pwdFeedback.style.display = 'block';
        } else {
          pwdFeedback.textContent = data.error || 'Failed to update password.';
          pwdFeedback.className = 'feedback-msg error';
          pwdFeedback.style.display = 'block';
        }
      } catch (err) {
        pwdFeedback.textContent = 'Error changing password.';
        pwdFeedback.className = 'feedback-msg error';
        pwdFeedback.style.display = 'block';
      }
    });
  }

  // ==========================================================================
  // 14. ADMIN PANEL (RBAC GOVERNED)
  // ==========================================================================
  async function loadAdminDashboard() {
    try {
      const res = await fetch('/api/admin/metrics', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.metrics) {
        const m = data.metrics;
        const usersEl = document.getElementById('adminMetricUsers');
        if (usersEl) usersEl.textContent = m.totalUsers || 0;
        const scansEl = document.getElementById('adminMetricScans');
        if (scansEl) scansEl.textContent = m.totalScans || 0;
        const secEl = document.getElementById('adminMetricSecurity');
        if (secEl) secEl.textContent = m.totalSecurityFindings || 0;
        const scoreEl = document.getElementById('adminMetricScore');
        if (scoreEl) scoreEl.textContent = m.avgScore ? `${Math.round(m.avgScore)}/100` : '--';
      }

      // Load recent audit logs
      const auditRes = await fetch('/api/admin/audit-logs', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const auditData = await auditRes.json();
      const stream = document.getElementById('adminAuditStream');
      if (stream && auditData.success && auditData.logs) {
        if (auditData.logs.length === 0) {
          stream.innerHTML = '<div style="padding:12px; font-size:0.8rem; color:var(--text-dim);">No audit events recorded yet.</div>';
        } else {
          let html = '';
          auditData.logs.slice(0, 6).forEach(log => {
            const timeStr = new Date(log.timestamp).toLocaleTimeString();
            html += `
              <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border-glass); font-size:0.8rem;">
                <span style="color:var(--text-main); font-weight:600;">${escapeHtml(log.action || log.event || 'System Event')}</span>
                <span style="color:var(--text-dim);">${timeStr}</span>
              </div>
            `;
          });
          stream.innerHTML = html;
        }
      }
    } catch (e) {}
  }

  // Admin Profile View
  function populateAdminProfileView() {
    if (!currentUser) return;
    const adminProfName = document.getElementById('adminProfName');
    const adminProfEmail = document.getElementById('adminProfEmail');
    const adminProfAvatar = document.getElementById('adminProfAvatar');
    const adminEditName = document.getElementById('adminEditName');
    const adminEditBio = document.getElementById('adminEditBio');

    if (adminProfName) adminProfName.textContent = currentUser.name || currentUser.username;
    if (adminProfEmail) adminProfEmail.textContent = currentUser.email || 'admin@codeinsight.local';
    if (adminProfAvatar) adminProfAvatar.textContent = (currentUser.avatar || 'AD').slice(0, 2).toUpperCase();
    if (adminEditName) adminEditName.value = currentUser.name || '';
    if (adminEditBio) adminEditBio.value = currentUser.bio || '';
  }

  const formAdminProfile = document.getElementById('formAdminProfile');
  const adminProfFeedback = document.getElementById('adminProfFeedback');
  if (formAdminProfile) {
    formAdminProfile.addEventListener('submit', async (e) => {
      e.preventDefault();
      adminProfFeedback.style.display = 'none';
      const name = document.getElementById('adminEditName').value.trim();
      const bio = document.getElementById('adminEditBio').value.trim();

      try {
        const res = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({ name, bio })
        });
        const data = await res.json();
        if (data.success && data.user) {
          currentUser = data.user;
          applyLoggedInUI();
          adminProfFeedback.textContent = 'Admin profile updated successfully!';
          adminProfFeedback.className = 'feedback-msg success';
          adminProfFeedback.style.display = 'block';
        } else {
          adminProfFeedback.textContent = data.error || 'Failed to update.';
          adminProfFeedback.className = 'feedback-msg error';
          adminProfFeedback.style.display = 'block';
        }
      } catch (err) {
        adminProfFeedback.textContent = 'Network error updating admin profile.';
        adminProfFeedback.className = 'feedback-msg error';
        adminProfFeedback.style.display = 'block';
      }
    });
  }

  // Admin User Management View
  async function loadAdminUsers() {
    const tbody = document.getElementById('adminUsersTbody');
    if (!tbody) return;

    try {
      const res = await fetch('/api/admin/users', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.users) {
        let html = '';
        data.users.forEach(u => {
          const isRootAdmin = u.username === 'admin' || u.id === 'usr-admin-01';
          const roleBadgeClass = u.role === 'admin' ? 'role-admin' : 'role-user';
          const statusBadgeClass = u.status === 'active' ? 'badge-success' : 'badge-danger';

          html += `
            <tr>
              <td>
                <div style="font-weight:700; color:var(--text-main);">${escapeHtml(u.name || u.username)}</div>
                <div style="font-size:0.75rem; color:var(--text-dim);">${escapeHtml(u.username)}</div>
              </td>
              <td>${escapeHtml(u.email)}</td>
              <td><span class="role-pill ${roleBadgeClass}">${(u.role || 'user').toUpperCase()}</span></td>
              <td><span class="badge ${statusBadgeClass}">${(u.status || 'active').toUpperCase()}</span></td>
              <td>${u.createdAt ? new Date(u.createdAt).toLocaleDateString() : 'N/A'}</td>
              <td>
                <div style="display:flex; gap:6px; flex-wrap:wrap;">
                  ${isRootAdmin ? `
                    <span style="font-size:0.75rem; color:var(--text-dim); font-weight:700;">Root Protected</span>
                  ` : `
                    <button class="btn btn-secondary btn-sm btnAdminToggleRole" data-id="${u.id}" data-role="${u.role}">
                      ${u.role === 'admin' ? 'Demote' : 'Promote'}
                    </button>
                    <button class="btn btn-secondary btn-sm btnAdminToggleStatus" data-id="${u.id}" data-status="${u.status}">
                      ${u.status === 'active' ? 'Suspend' : 'Activate'}
                    </button>
                    <button class="btn btn-ghost btn-sm btnAdminDeleteUser" data-id="${u.id}" style="color:var(--danger);">
                      Delete
                    </button>
                  `}
                </div>
              </td>
            </tr>
          `;
        });
        tbody.innerHTML = html;

        // Bind Action Buttons
        tbody.querySelectorAll('.btnAdminToggleRole').forEach(btn => {
          btn.addEventListener('click', async () => {
            const userId = btn.dataset.id;
            const newRole = btn.dataset.role === 'admin' ? 'user' : 'admin';
            try {
              const r = await fetch(`/api/admin/users/${userId}/role`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
                body: JSON.stringify({ role: newRole })
              });
              const d = await r.json();
              if (d.success) {
                showPageAlert(`User role changed to ${newRole}.`, 'success');
                loadAdminUsers();
              } else {
                showPageAlert(d.message || d.error || 'Failed to change role.', 'error');
              }
            } catch (e) {
              showPageAlert('Error modifying user role.', 'error');
            }
          });
        });

        tbody.querySelectorAll('.btnAdminToggleStatus').forEach(btn => {
          btn.addEventListener('click', async () => {
            const userId = btn.dataset.id;
            const newStatus = btn.dataset.status === 'active' ? 'suspended' : 'active';
            try {
              const r = await fetch(`/api/admin/users/${userId}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
                body: JSON.stringify({ status: newStatus })
              });
              const d = await r.json();
              if (d.success) {
                showPageAlert(`User status updated to ${newStatus}.`, 'success');
                loadAdminUsers();
              } else {
                showPageAlert(d.message || d.error || 'Failed to change status.', 'error');
              }
            } catch (e) {
              showPageAlert('Error changing user status.', 'error');
            }
          });
        });

        tbody.querySelectorAll('.btnAdminDeleteUser').forEach(btn => {
          btn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to delete this user account?')) return;
            const userId = btn.dataset.id;
            try {
              const r = await fetch(`/api/admin/users/${userId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${authToken}` }
              });
              const d = await r.json();
              if (d.success) {
                showPageAlert('User account deleted.', 'info');
                loadAdminUsers();
              } else {
                showPageAlert(d.error || 'Failed to delete user.', 'error');
              }
            } catch (e) {
              showPageAlert('Error deleting user account.', 'error');
            }
          });
        });
      }
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Error loading user directory.</td></tr>';
    }
  }

  // Admin Analysis Logs View
  async function loadAdminLogs() {
    const tbody = document.getElementById('adminLogsTbody');
    if (!tbody) return;

    const langFilter = document.getElementById('filterLogsLanguage') ? document.getElementById('filterLogsLanguage').value : '';

    try {
      const url = langFilter ? `/api/admin/logs?language=${encodeURIComponent(langFilter)}` : '/api/admin/logs';
      const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.logs) {
        if (data.logs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No analysis logs recorded.</td></tr>';
          return;
        }

        let html = '';
        data.logs.forEach(log => {
          const dateStr = new Date(log.timestamp).toLocaleString();
          const scoreClass = log.healthScore >= 90 ? 'badge-success' : log.healthScore >= 70 ? 'badge-warning' : 'badge-danger';
          html += `
            <tr>
              <td>${dateStr}</td>
              <td>${escapeHtml(log.username || 'user')}</td>
              <td><span class="font-mono">${(log.language || 'code').toUpperCase()}</span></td>
              <td><span class="badge ${scoreClass}">${log.healthScore}/100</span></td>
              <td style="color:var(--danger);">${log.errorsCount || 0}</td>
              <td style="color:var(--warning);">${log.warningsCount || 0}</td>
              <td style="color:var(--purple-accent);">${log.securityCount || 0}</td>
              <td>
                <button class="btn btn-secondary btn-sm btnInspectLog" data-id="${log.id}">Inspect</button>
              </td>
            </tr>
          `;
        });
        tbody.innerHTML = html;

        tbody.querySelectorAll('.btnInspectLog').forEach(btn => {
          btn.addEventListener('click', () => {
            const logItem = data.logs.find(l => l.id === btn.dataset.id);
            if (logItem) openScanDetailModal(logItem);
          });
        });
      }
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="8" class="table-empty">Error loading analysis logs.</td></tr>';
    }
  }

  const filterLogsLanguage = document.getElementById('filterLogsLanguage');
  if (filterLogsLanguage) {
    filterLogsLanguage.addEventListener('change', loadAdminLogs);
  }

  // Scan Detail Inspection Modal
  function openScanDetailModal(log) {
    scanModalActiveCode = log.codeSnippet || '';
    scanModalActiveLang = log.language || 'javascript';

    if (scanModalTitle) scanModalTitle.textContent = `Scan Record: ${log.id}`;
    if (scanModalSubtitle) scanModalSubtitle.textContent = `User: ${log.username} • ${new Date(log.timestamp).toLocaleString()}`;

    if (scanModalContent) {
      scanModalContent.innerHTML = `
        <div style="display:flex; gap:12px; margin-bottom:14px;">
          <span class="badge badge-info">Language: ${log.language.toUpperCase()}</span>
          <span class="badge ${log.healthScore >= 80 ? 'badge-success' : 'badge-warning'}">Score: ${log.healthScore}/100</span>
          <span class="badge badge-danger">Errors: ${log.errorsCount || 0}</span>
          <span class="badge badge-purple">Security: ${log.securityCount || 0}</span>
        </div>
        <div style="margin-bottom:12px;">
          <strong style="font-size:0.8rem; color:var(--text-muted);">SOURCE SNIPPET:</strong>
          <pre style="background:#080D18; padding:12px; border-radius:var(--radius-sm); font-family:var(--font-mono); font-size:0.8rem; margin-top:6px; max-height:220px; overflow:auto;">${escapeHtml(log.codeSnippet || '// No code saved')}</pre>
        </div>
        <div>
          <strong style="font-size:0.8rem; color:var(--text-muted);">FINDINGS RECORDED:</strong>
          <div style="margin-top:6px; display:flex; flex-direction:column; gap:8px;">
            ${(log.findings || []).map(f => `
              <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-glass); padding:8px 12px; border-radius:4px; font-size:0.8rem;">
                <span class="badge ${f.severity === 'critical' || f.severity === 'high' ? 'badge-danger' : 'badge-warning'}">${f.severity}</span>
                <strong style="margin-left:6px;">Line ${f.line}: ${escapeHtml(f.title || f.ruleName)}</strong>
                <p style="color:var(--text-dim); margin-top:2px;">${escapeHtml(f.description || f.explanation)}</p>
              </div>
            `).join('') || '<div style="color:var(--text-dim); font-size:0.8rem;">No findings recorded.</div>'}
          </div>
        </div>
      `;
    }

    if (scanDetailModal) scanDetailModal.style.display = 'flex';
  }

  function closeScanDetailModal() {
    if (scanDetailModal) scanDetailModal.style.display = 'none';
  }

  if (btnCloseScanModal) btnCloseScanModal.addEventListener('click', closeScanDetailModal);
  if (btnCloseScanModalBtn) btnCloseScanModalBtn.addEventListener('click', closeScanDetailModal);
  if (btnScanModalLoadInAnalyzer) {
    btnScanModalLoadInAnalyzer.addEventListener('click', () => {
      closeScanDetailModal();
      analyzerCodeInput.value = scanModalActiveCode;
      updateEditorStats();
      if (analyzerLangSelect) {
        analyzerLangSelect.value = scanModalActiveLang;
        analyzerLangSelect.dispatchEvent(new Event('change'));
      }
      switchTab('analyzer');
      showPageAlert('Source loaded into Code Analyzer.', 'info');
    });
  }

  // Admin Reports View
  async function loadAdminReports() {
    try {
      const res = await fetch('/api/admin/reports', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.report) {
        const r = data.report;
        const vulnContainer = document.getElementById('reportVulnBreakdown');
        if (vulnContainer && r.vulnerabilitiesByCategory) {
          let html = '';
          const cats = Object.entries(r.vulnerabilitiesByCategory);
          if (cats.length === 0) {
            html = '<div style="font-size:0.85rem; color:var(--text-dim);">No vulnerabilities recorded across scans.</div>';
          } else {
            cats.forEach(([cat, count]) => {
              html += `
                <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.85rem; border-bottom:1px solid var(--border-glass); padding-bottom:6px;">
                  <span style="color:var(--text-main); font-weight:600;">${escapeHtml(cat)}</span>
                  <span class="badge badge-danger">${count}</span>
                </div>
              `;
            });
          }
          vulnContainer.innerHTML = html;
        }

        const langContainer = document.getElementById('reportLangBreakdown');
        if (langContainer && r.scansByLanguage) {
          let html = '';
          const langs = Object.entries(r.scansByLanguage);
          if (langs.length === 0) {
            html = '<div style="font-size:0.85rem; color:var(--text-dim);">No language analyses logged yet.</div>';
          } else {
            langs.forEach(([lang, count]) => {
              html += `
                <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.85rem; border-bottom:1px solid var(--border-glass); padding-bottom:6px;">
                  <span class="font-mono">${lang.toUpperCase()}</span>
                  <strong style="color:var(--primary);">${count} scans</strong>
                </div>
              `;
            });
          }
          langContainer.innerHTML = html;
        }
      }
    } catch (e) {}
  }

  const btnAdminExportCsv = document.getElementById('btnAdminExportCsv');
  if (btnAdminExportCsv) {
    btnAdminExportCsv.addEventListener('click', downloadCsvExport);
  }

  // Admin System Settings View
  async function loadAdminSettings() {
    try {
      const res = await fetch('/api/admin/settings', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      const data = await res.json();
      if (data.success && data.settings) {
        const s = data.settings;
        const nameEl = document.getElementById('sysPlatformName');
        if (nameEl && s.platformName) nameEl.value = s.platformName;
        const regEl = document.getElementById('sysAllowReg');
        if (regEl && s.allowRegistration !== undefined) regEl.checked = s.allowRegistration;
        const sizeEl = document.getElementById('sysMaxFileSize');
        if (sizeEl && s.maxZipArchiveMb) sizeEl.value = s.maxZipArchiveMb;
        const langEl = document.getElementById('sysDefaultLang');
        if (langEl && s.defaultLanguage) langEl.value = s.defaultLanguage;
        const timeEl = document.getElementById('sysSessionTimeout');
        if (timeEl && s.sessionTimeoutMinutes) timeEl.value = s.sessionTimeoutMinutes;
      }
    } catch (e) {}
  }

  const formSystemSettings = document.getElementById('formSystemSettings');
  const sysSettingsFeedback = document.getElementById('sysSettingsFeedback');
  if (formSystemSettings) {
    formSystemSettings.addEventListener('submit', async (e) => {
      e.preventDefault();
      sysSettingsFeedback.style.display = 'none';

      const platformName = document.getElementById('sysPlatformName').value.trim();
      const allowRegistration = document.getElementById('sysAllowReg').checked;
      const maxZipArchiveMb = parseInt(document.getElementById('sysMaxFileSize').value, 10);
      const defaultLanguage = document.getElementById('sysDefaultLang').value;
      const sessionTimeoutMinutes = parseInt(document.getElementById('sysSessionTimeout').value, 10);

      try {
        const res = await fetch('/api/admin/settings', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({
            platformName,
            allowRegistration,
            maxZipArchiveMb,
            defaultLanguage,
            sessionTimeoutMinutes
          })
        });
        const data = await res.json();
        if (data.success) {
          document.title = `${platformName || 'CodeInsight'} – Multi-Language Static Code Analysis Platform`;
          const brandTitle = document.querySelector('.brand-title');
          if (brandTitle && brandTitle.firstChild) brandTitle.firstChild.textContent = (platformName || 'CodeInsight') + ' ';
          if (analyzerLangSelect && defaultLanguage) {
            analyzerLangSelect.value = defaultLanguage;
            analyzerLangSelect.dispatchEvent(new Event('change'));
          }
          sysSettingsFeedback.textContent = 'Platform configuration saved!';
          sysSettingsFeedback.className = 'feedback-msg success';
          sysSettingsFeedback.style.display = 'block';
        } else {
          sysSettingsFeedback.textContent = data.message || data.error || 'Failed to save system settings.';
          sysSettingsFeedback.className = 'feedback-msg error';
          sysSettingsFeedback.style.display = 'block';
        }
      } catch (err) {
        sysSettingsFeedback.textContent = 'Error connecting to admin settings API.';
        sysSettingsFeedback.className = 'feedback-msg error';
        sysSettingsFeedback.style.display = 'block';
      }
    });
  }

  // ==========================================================================
  // 15. THEME TOGGLES & UTILITIES
  // ==========================================================================
  const THEMES = ['dark', 'cyberpunk', 'slate', 'light'];
  const THEME_NAMES = {
    dark: 'Obsidian Dark',
    cyberpunk: 'Cyberpunk Neon',
    slate: 'Slate Modern Pro',
    light: 'Light Porcelain'
  };

  function applyTheme(themeName) {
    const valid = THEMES.includes(themeName) ? themeName : 'dark';
    document.documentElement.setAttribute('data-theme', valid);
    localStorage.setItem('codeinsight-theme', valid);
    const setThemeEl = document.getElementById('setTheme');
    if (setThemeEl) setThemeEl.value = valid;
    return valid;
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const nextIdx = (THEMES.indexOf(current) + 1) % THEMES.length;
    const nextTheme = THEMES[nextIdx >= 0 ? nextIdx : 0];
    applyTheme(nextTheme);
    showPageAlert(`Theme: ${THEME_NAMES[nextTheme] || nextTheme}`, 'info');
  }

  const btnThemeToggle = document.getElementById('btnThemeToggle');
  if (btnThemeToggle) btnThemeToggle.addEventListener('click', toggleTheme);
  const btnSideThemeToggle = document.getElementById('btnSideThemeToggle');
  if (btnSideThemeToggle) btnSideThemeToggle.addEventListener('click', toggleTheme);

  // Restore saved theme on startup
  const savedTheme = localStorage.getItem('codeinsight-theme');
  if (savedTheme) {
    applyTheme(savedTheme);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ==========================================================================
  // 16. INITIALIZATION & ROUTING BOOTSTRAP
  // ==========================================================================
  // Restore the last working draft so applying a fix or navigating between tabs
  // does not silently discard the user's current code. Legacy keys remain supported.
  try {
    const savedWorkingCode = localStorage.getItem('codeinsight_working_code');
    const savedLegacyCode = localStorage.getItem('codeinsight_code');
    const savedWorkingLanguage = localStorage.getItem('codeinsight_working_language');
    const savedLegacyLanguage = localStorage.getItem('codeinsight_language');
    if (analyzerCodeInput && savedWorkingCode !== null) {
      analyzerCodeInput.value = savedWorkingCode;
    } else if (analyzerCodeInput && savedLegacyCode !== null && !analyzerCodeInput.value) {
      analyzerCodeInput.value = savedLegacyCode;
    }
    const savedLanguage = savedWorkingLanguage || savedLegacyLanguage;
    if (analyzerLangSelect && savedLanguage) {
      const hasOption = Array.from(analyzerLangSelect.options).some(option => option.value === savedLanguage);
      if (hasOption) analyzerLangSelect.value = savedLanguage;
    }
    if (analyzerCodeInput) updateEditorStats();
  } catch (storageError) {
    console.warn('Could not restore working draft.', storageError);
  }

  fetch('/api/config')
    .then(response => response.ok ? response.json() : null)
    .then(config => {
      const defaultLanguage = config && config.defaultLanguage ? config.defaultLanguage : 'javascript';
      if (config && config.platformName) {
        document.title = `${config.platformName} – Multi-Language Static Code Analysis Platform`;
        const brandTitle = document.querySelector('.brand-title');
        if (brandTitle && brandTitle.firstChild) brandTitle.firstChild.textContent = config.platformName + ' ';
      }
      if (analyzerLangSelect && !localStorage.getItem('codeinsight_language') && !localStorage.getItem('codeinsight_working_language')) {
        analyzerLangSelect.value = defaultLanguage;
        populatePresetsForLang(defaultLanguage);
      } else {
        populatePresetsForLang(analyzerLangSelect ? analyzerLangSelect.value : defaultLanguage);
      }
    })
    .catch(() => populatePresetsForLang('javascript'));
  if (analyzerCodeInput && analyzerCodeInput.value) updateEditorStats();

  checkSession().then(() => {
    // Read window hash or default to dashboard
    const hash = window.location.hash.replace('#', '');
    if (hash && TAB_NAMES[hash]) {
      switchTab(hash);
    } else {
      switchTab(currentUser ? (currentUser.role === 'admin' ? 'admin-dashboard' : 'user-dashboard') : 'user-dashboard');
    }
  });

  // Handle browser back/forward buttons
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace('#', '');
    if (hash && TAB_NAMES[hash]) {
      switchTab(hash);
    }
  });

});
