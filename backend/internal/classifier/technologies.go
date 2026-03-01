package classifier

import (
	"regexp"
	"strings"
)

// Technology represents a detected technology
type Technology struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence"`
}

// TechnologyFingerprints holds all detection patterns
type TechnologyFingerprints struct {
	Headers  map[string][]HeaderFingerprint
	HTML     []HTMLFingerprint
	URLPaths []PathFingerprint
	Scripts  []ScriptFingerprint
	MetaTags []MetaFingerprint
}

// HeaderFingerprint matches based on HTTP headers
type HeaderFingerprint struct {
	Name              string
	Pattern           *regexp.Regexp
	Category          string
	VersionExtraction func(string) string
	Confidence        float64
}

// HTMLFingerprint matches based on HTML content
type HTMLFingerprint struct {
	Name       string
	Pattern    *regexp.Regexp
	Category   string
	Confidence float64
}

// PathFingerprint matches based on URL paths
type PathFingerprint struct {
	Name       string
	Pattern    *regexp.Regexp
	Category   string
	Confidence float64
}

// ScriptFingerprint matches based on script sources
type ScriptFingerprint struct {
	Name       string
	Pattern    *regexp.Regexp
	Category   string
	Confidence float64
}

// MetaFingerprint matches based on meta tags
type MetaFingerprint struct {
	Name           string
	NameAttr       string
	ContentPattern *regexp.Regexp
	Category       string
	Confidence     float64
}

// NewTechnologyFingerprints creates the complete fingerprint database
func NewTechnologyFingerprints() *TechnologyFingerprints {
	return &TechnologyFingerprints{
		Headers:  initHeaderFingerprints(),
		HTML:     initHTMLFingerprints(),
		URLPaths: initPathFingerprints(),
		Scripts:  initScriptFingerprints(),
		MetaTags: initMetaFingerprints(),
	}
}

// initHeaderFingerprints initializes HTTP header fingerprints
func initHeaderFingerprints() map[string][]HeaderFingerprint {
	return map[string][]HeaderFingerprint{
		"Server": {
			{Name: "Apache", Pattern: regexp.MustCompile(`(?i)apache[/\s]?([\d.]+)?`), Category: "Web Server", VersionExtraction: extractVersion, Confidence: 0.9},
			{Name: "Nginx", Pattern: regexp.MustCompile(`(?i)nginx[/\s]?([\d.]+)?`), Category: "Web Server", VersionExtraction: extractVersion, Confidence: 0.95},
			{Name: "Microsoft-IIS", Pattern: regexp.MustCompile(`(?i)Microsoft-IIS[/\s]?([\d.]+)`), Category: "Web Server", VersionExtraction: extractVersion, Confidence: 0.95},
			{Name: "Caddy", Pattern: regexp.MustCompile(`(?i)caddy`), Category: "Web Server", Confidence: 0.9},
			{Name: "lighttpd", Pattern: regexp.MustCompile(`(?i)lighttpd[/\s]?([\d.]+)?`), Category: "Web Server", VersionExtraction: extractVersion, Confidence: 0.9},
			{Name: "Tomcat", Pattern: regexp.MustCompile(`(?i)Apache-Coyote|Tomcat`), Category: "Application Server", Confidence: 0.85},
			{Name: "Jetty", Pattern: regexp.MustCompile(`(?i)Jetty[/\s]?([\d.]+)?`), Category: "Application Server", VersionExtraction: extractVersion, Confidence: 0.85},
			{Name: "Gunicorn", Pattern: regexp.MustCompile(`(?i)gunicorn[/\s]?([\d.]+)?`), Category: "Application Server", VersionExtraction: extractVersion, Confidence: 0.85},
			{Name: "uWSGI", Pattern: regexp.MustCompile(`(?i)uWSGI[/\s]?([\d.]+)?`), Category: "Application Server", VersionExtraction: extractVersion, Confidence: 0.85},
		},
		"X-Powered-By": {
			{Name: "PHP", Pattern: regexp.MustCompile(`(?i)PHP[/\s]?([\d.]+)?`), Category: "Programming Language", VersionExtraction: extractVersion, Confidence: 0.95},
			{Name: "ASP.NET", Pattern: regexp.MustCompile(`(?i)ASP\.NET`), Category: "Framework", Confidence: 0.95},
			{Name: "Express", Pattern: regexp.MustCompile(`(?i)Express`), Category: "Framework", Confidence: 0.85},
		},
		"X-Generator": {
			{Name: "Drupal", Pattern: regexp.MustCompile(`(?i)Drupal\s*([\d.]+)?`), Category: "CMS", VersionExtraction: extractVersion, Confidence: 0.95},
			{Name: "WordPress", Pattern: regexp.MustCompile(`(?i)WordPress`), Category: "CMS", Confidence: 0.9},
			{Name: "Joomla", Pattern: regexp.MustCompile(`(?i)Joomla`), Category: "CMS", Confidence: 0.9},
		},
		"X-Runtime": {
			{Name: "Ruby on Rails", Pattern: regexp.MustCompile(`(?i)Rails`), Category: "Framework", Confidence: 0.9},
		},
		"X-Frame-Options": {
			{Name: "Security Headers", Pattern: regexp.MustCompile(`.+`), Category: "Security", Confidence: 0.7},
		},
		"Content-Security-Policy": {
			{Name: "CSP", Pattern: regexp.MustCompile(`.+`), Category: "Security", Confidence: 0.8},
		},
		"Strict-Transport-Security": {
			{Name: "HSTS", Pattern: regexp.MustCompile(`.+`), Category: "Security", Confidence: 0.8},
		},
		"CF-Ray": {
			{Name: "Cloudflare", Pattern: regexp.MustCompile(`.+`), Category: "CDN", Confidence: 1.0},
		},
		"CF-Cache-Status": {
			{Name: "Cloudflare", Pattern: regexp.MustCompile(`.+`), Category: "CDN", Confidence: 1.0},
		},
		"X-Vercel-Id": {
			{Name: "Vercel", Pattern: regexp.MustCompile(`.+`), Category: "Hosting", Confidence: 1.0},
		},
		"X-Powered-By-Picombo": {
			{Name: "Picombo", Pattern: regexp.MustCompile(`.+`), Category: "Framework", Confidence: 0.8},
		},
		"X-AspNet-Version": {
			{Name: "ASP.NET", Pattern: regexp.MustCompile(`([\d.]+)`), Category: "Framework", VersionExtraction: extractVersion, Confidence: 0.95},
		},
		"X-AspNetMvc-Version": {
			{Name: "ASP.NET MVC", Pattern: regexp.MustCompile(`([\d.]+)`), Category: "Framework", VersionExtraction: extractVersion, Confidence: 0.95},
		},
		"X-Drupal-Cache": {
			{Name: "Drupal", Pattern: regexp.MustCompile(`.+`), Category: "CMS", Confidence: 0.9},
		},
		"X-Drupal-Dynamic-Cache": {
			{Name: "Drupal", Pattern: regexp.MustCompile(`.+`), Category: "CMS", Confidence: 0.9},
		},
		"X-Shopify-Stage": {
			{Name: "Shopify", Pattern: regexp.MustCompile(`.+`), Category: "E-commerce", Confidence: 0.95},
		},
	}
}

// initHTMLFingerprints initializes HTML content fingerprints
func initHTMLFingerprints() []HTMLFingerprint {
	return []HTMLFingerprint{
		// AI/ML Frameworks
		{Name: "Gradio", Pattern: regexp.MustCompile(`(?i)<gradio-app|<gradio-model3d|gradioApp`), Category: "AI/ML Framework", Confidence: 0.95},
		{Name: "Streamlit", Pattern: regexp.MustCompile(`(?i)streamlit|stApp|stButton|stSidebar`), Category: "AI/ML Framework", Confidence: 0.95},
		{Name: "Chainlit", Pattern: regexp.MustCompile(`(?i)chainlit|c-message|cl-chat`), Category: "AI/ML Framework", Confidence: 0.9},
		{Name: "OpenWebUI", Pattern: regexp.MustCompile(`(?i)open-webui|openwebui`), Category: "AI Chat Interface", Confidence: 0.9},
		{Name: "ChatGPT Clone", Pattern: regexp.MustCompile(`(?i)chatgpt-clone|chat-interface|ai-chat`), Category: "AI Chat Interface", Confidence: 0.8},

		// JavaScript Frameworks
		{Name: "React", Pattern: regexp.MustCompile(`(?i)react-root|data-reactroot|__REACT__|reactjs`), Category: "JavaScript Framework", Confidence: 0.85},
		{Name: "Next.js", Pattern: regexp.MustCompile(`(?i)__NEXT_DATA__|__NEXT_LOADER__`), Category: "JavaScript Framework", Confidence: 0.95},
		{Name: "Vue.js", Pattern: regexp.MustCompile(`(?i)vue-|v-bind|v-if|v-for|data-v-`), Category: "JavaScript Framework", Confidence: 0.85},
		{Name: "Angular", Pattern: regexp.MustCompile(`(?i)ng-|angular|ngApp|ng-controller`), Category: "JavaScript Framework", Confidence: 0.85},
		{Name: "Svelte", Pattern: regexp.MustCompile(`(?i)svelte|svelte-`), Category: "JavaScript Framework", Confidence: 0.85},
		{Name: "jQuery", Pattern: regexp.MustCompile(`(?i)jquery[/\s]?([\d.]+)?`), Category: "JavaScript Library", Confidence: 0.8},

		// CSS Frameworks
		{Name: "Bootstrap", Pattern: regexp.MustCompile(`(?i)bootstrap|container-fluid|row-fluid`), Category: "CSS Framework", Confidence: 0.85},
		{Name: "Tailwind CSS", Pattern: regexp.MustCompile(`(?i)tailwind|tw-|\btw-[a-z]+`), Category: "CSS Framework", Confidence: 0.85},
		{Name: "Material-UI", Pattern: regexp.MustCompile(`(?i)Mui[A-Z]|material-ui`), Category: "CSS Framework", Confidence: 0.85},
		{Name: "Bulma", Pattern: regexp.MustCompile(`(?i)bulma|is-primary|is-info`), Category: "CSS Framework", Confidence: 0.8},

		// CMS
		{Name: "WordPress", Pattern: regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`), Category: "CMS", Confidence: 0.9},
		{Name: "Drupal", Pattern: regexp.MustCompile(`(?i)drupal|sites/default|drupalSettings`), Category: "CMS", Confidence: 0.9},
		{Name: "Joomla", Pattern: regexp.MustCompile(`(?i)joomla|/media/jui/`), Category: "CMS", Confidence: 0.9},
		{Name: "Magento", Pattern: regexp.MustCompile(`(?i)magento|Mage\.`), Category: "E-commerce", Confidence: 0.9},
		{Name: "Shopify", Pattern: regexp.MustCompile(`(?i)shopify|myshopify`), Category: "E-commerce", Confidence: 0.9},
		{Name: "Wix", Pattern: regexp.MustCompile(`(?i)wix|static.wixstatic`), Category: "Website Builder", Confidence: 0.9},

		// Backend Frameworks
		{Name: "Django", Pattern: regexp.MustCompile(`(?i)django|csrfmiddlewaretoken`), Category: "Web Framework", Confidence: 0.85},
		{Name: "Flask", Pattern: regexp.MustCompile(`(?i)flask`), Category: "Web Framework", Confidence: 0.8},
		{Name: "Laravel", Pattern: regexp.MustCompile(`(?i)laravel`), Category: "Web Framework", Confidence: 0.85},
		{Name: "Ruby on Rails", Pattern: regexp.MustCompile(`(?i)rails|csrf-param`), Category: "Web Framework", Confidence: 0.85},
		{Name: "Spring Boot", Pattern: regexp.MustCompile(`(?i)spring|th:`), Category: "Web Framework", Confidence: 0.8},
		{Name: "ASP.NET", Pattern: regexp.MustCompile(`(?i)__VIEWSTATE|aspnet`), Category: "Web Framework", Confidence: 0.9},

		// API Documentation
		{Name: "Swagger UI", Pattern: regexp.MustCompile(`(?i)swagger|swagger-ui`), Category: "API Documentation", Confidence: 0.95},
		{Name: "Redoc", Pattern: regexp.MustCompile(`(?i)redoc`), Category: "API Documentation", Confidence: 0.95},
		{Name: "GraphiQL", Pattern: regexp.MustCompile(`(?i)graphiql`), Category: "API Documentation", Confidence: 0.95},

		// Analytics
		{Name: "Google Analytics", Pattern: regexp.MustCompile(`(?i)google-analytics|gtag|ga\(`), Category: "Analytics", Confidence: 0.9},
		{Name: "Mixpanel", Pattern: regexp.MustCompile(`(?i)mixpanel`), Category: "Analytics", Confidence: 0.9},
		{Name: "Segment", Pattern: regexp.MustCompile(`(?i)segment\.io|analytics\.js`), Category: "Analytics", Confidence: 0.85},

		// Chat/Communication
		{Name: "Intercom", Pattern: regexp.MustCompile(`(?i)intercom|intercomSettings`), Category: "Customer Support", Confidence: 0.9},
		{Name: "Zendesk", Pattern: regexp.MustCompile(`(?i)zendesk`), Category: "Customer Support", Confidence: 0.9},
		{Name: "Freshdesk", Pattern: regexp.MustCompile(`(?i)freshdesk`), Category: "Customer Support", Confidence: 0.9},
	}
}

// initPathFingerprints initializes URL path fingerprints
func initPathFingerprints() []PathFingerprint {
	return []PathFingerprint{
		{Name: "API", Pattern: regexp.MustCompile(`(?i)/api[/v]|/v\d+/|/rest/`), Category: "API", Confidence: 0.8},
		{Name: "GraphQL", Pattern: regexp.MustCompile(`(?i)/graphql|/gql`), Category: "API", Confidence: 0.95},
		{Name: "Swagger", Pattern: regexp.MustCompile(`(?i)/swagger|/swagger-ui|/api-docs`), Category: "API Documentation", Confidence: 0.9},
		{Name: "OpenAPI", Pattern: regexp.MustCompile(`(?i)/openapi|/openapi\.json`), Category: "API Documentation", Confidence: 0.9},
		{Name: "WordPress Admin", Pattern: regexp.MustCompile(`(?i)/wp-admin|/wp-login`), Category: "CMS Admin", Confidence: 0.95},
		{Name: "PHPMyAdmin", Pattern: regexp.MustCompile(`(?i)/phpmyadmin|/pma`), Category: "Database Admin", Confidence: 0.95},
		{Name: "Admin Panel", Pattern: regexp.MustCompile(`(?i)/admin|/administrator|/dashboard`), Category: "Admin Panel", Confidence: 0.7},
		{Name: "AI Chat", Pattern: regexp.MustCompile(`(?i)/chat|/chatbot|/assistant`), Category: "AI Interface", Confidence: 0.75},
		{Name: "WebSocket", Pattern: regexp.MustCompile(`(?i)/ws|/websocket|/socket`), Category: "WebSocket", Confidence: 0.75},
	}
}

// initScriptFingerprints initializes JavaScript file fingerprints
func initScriptFingerprints() []ScriptFingerprint {
	return []ScriptFingerprint{
		{Name: "React", Pattern: regexp.MustCompile(`(?i)react[.-\s]?([\d.]+)?\.js`), Category: "JavaScript Framework", Confidence: 0.9},
		{Name: "Vue.js", Pattern: regexp.MustCompile(`(?i)vue[.-\s]?([\d.]+)?\.js`), Category: "JavaScript Framework", Confidence: 0.9},
		{Name: "Angular", Pattern: regexp.MustCompile(`(?i)angular[.-\s]?([\d.]+)?\.js`), Category: "JavaScript Framework", Confidence: 0.9},
		{Name: "jQuery", Pattern: regexp.MustCompile(`(?i)jquery[.-\s]?([\d.]+)?\.js`), Category: "JavaScript Library", Confidence: 0.9},
		{Name: "Bootstrap", Pattern: regexp.MustCompile(`(?i)bootstrap[.-\s]?([\d.]+)?\.js`), Category: "CSS Framework", Confidence: 0.9},
		{Name: "Lodash", Pattern: regexp.MustCompile(`(?i)lodash[.-\s]?([\d.]+)?\.js`), Category: "JavaScript Library", Confidence: 0.9},
		{Name: "TensorFlow.js", Pattern: regexp.MustCompile(`(?i)tensorflow|tf\.js`), Category: "ML Library", Confidence: 0.9},
		{Name: "Three.js", Pattern: regexp.MustCompile(`(?i)three[.-\s]?([\d.]+)?\.js`), Category: "3D Library", Confidence: 0.9},
	}
}

// initMetaFingerprints initializes meta tag fingerprints
func initMetaFingerprints() []MetaFingerprint {
	return []MetaFingerprint{
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)WordPress\s*([\d.]+)?`), Category: "CMS", Confidence: 0.95},
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)Drupal\s*([\d.]+)?`), Category: "CMS", Confidence: 0.95},
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)Joomla`), Category: "CMS", Confidence: 0.9},
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)Next\.js`), Category: "Framework", Confidence: 0.9},
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)Gatsby`), Category: "Framework", Confidence: 0.9},
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)Hugo`), Category: "Static Site Generator", Confidence: 0.9},
		{Name: "Generator", NameAttr: "generator", ContentPattern: regexp.MustCompile(`(?i)Jekyll`), Category: "Static Site Generator", Confidence: 0.9},
		{Name: "Viewport", NameAttr: "viewport", ContentPattern: regexp.MustCompile(`.+`), Category: "Mobile Responsive", Confidence: 0.6},
	}
}

// extractVersion extracts version from a string
func extractVersion(s string) string {
	versionPattern := regexp.MustCompile(`(\d+(?:\.\d+)*)`)
	matches := versionPattern.FindStringSubmatch(s)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// DetectTechnologies analyzes response data to detect technologies
func (tf *TechnologyFingerprints) DetectTechnologies(headers map[string][]string, body string, url string) []Technology {
	technologies := make(map[string]Technology)

	// Check headers
	for headerName, fingerprints := range tf.Headers {
		headerValue := strings.Join(headers[headerName], " ")
		if headerValue == "" {
			continue
		}
		for _, fp := range fingerprints {
			if fp.Pattern.MatchString(headerValue) {
				version := ""
				if fp.VersionExtraction != nil {
					version = fp.VersionExtraction(headerValue)
				}
				tech := Technology{
					Name:       fp.Name,
					Category:   fp.Category,
					Version:    version,
					Confidence: fp.Confidence,
				}
				// Keep highest confidence version
				if existing, ok := technologies[fp.Name]; !ok || existing.Confidence < tech.Confidence {
					technologies[fp.Name] = tech
				}
			}
		}
	}

	// Check URL paths
	for _, fp := range tf.URLPaths {
		if fp.Pattern.MatchString(url) {
			tech := Technology{
				Name:       fp.Name,
				Category:   fp.Category,
				Confidence: fp.Confidence,
			}
			if existing, ok := technologies[fp.Name]; !ok || existing.Confidence < tech.Confidence {
				technologies[fp.Name] = tech
			}
		}
	}

	// Check HTML patterns
	for _, fp := range tf.HTML {
		if fp.Pattern.MatchString(body) {
			tech := Technology{
				Name:       fp.Name,
				Category:   fp.Category,
				Confidence: fp.Confidence,
			}
			if existing, ok := technologies[fp.Name]; !ok || existing.Confidence < tech.Confidence {
				technologies[fp.Name] = tech
			}
		}
	}

	// Convert map to slice
	result := make([]Technology, 0, len(technologies))
	for _, tech := range technologies {
		result = append(result, tech)
	}

	return result
}

// IsAIApplication checks if detected technologies indicate an AI/LLM application
func (tf *TechnologyFingerprints) IsAIApplication(technologies []Technology) bool {
	aiCategories := map[string]bool{
		"AI/ML Framework":   true,
		"AI Chat Interface": true,
		"ML Library":        true,
	}

	aiNames := map[string]bool{
		"Gradio":        true,
		"Streamlit":     true,
		"Chainlit":      true,
		"OpenWebUI":     true,
		"ChatGPT Clone": true,
		"TensorFlow.js": true,
	}

	for _, tech := range technologies {
		if aiCategories[tech.Category] || aiNames[tech.Name] {
			return true
		}
	}

	return false
}

// GetCDNProvider checks headers to identify CDN provider
func GetCDNProvider(headers map[string][]string) (string, float64) {
	cdnHeaders := map[string]struct {
		Pattern string
		Name    string
	}{
		"CF-Ray":               {Name: "Cloudflare"},
		"CF-Cache-Status":      {Name: "Cloudflare"},
		"X-Akamai-Transformed": {Name: "Akamai"},
		"X-Cache":              {Name: "Generic CDN"},
		"X-Varnish":            {Name: "Varnish"},
		"X-Served-By":          {Name: "Fastly"},
		"X-Vercel-Id":          {Name: "Vercel"},
		"X-Timer":              {Name: "Fastly"},
		"X-Edge-Location":      {Name: "Generic Edge"},
		"X-CDN":                {Name: "Generic CDN"},
		"Via":                  {Pattern: "cloudfront", Name: "CloudFront"},
	}

	for header, info := range cdnHeaders {
		if values, ok := headers[header]; ok && len(values) > 0 {
			if info.Pattern != "" {
				for _, v := range values {
					if strings.Contains(strings.ToLower(v), info.Pattern) {
						return info.Name, 0.95
					}
				}
			} else {
				return info.Name, 1.0
			}
		}
	}

	return "", 0
}
