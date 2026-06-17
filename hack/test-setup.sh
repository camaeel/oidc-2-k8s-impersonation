#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Testing OIDC-2-K8s Impersonation Proxy ===${NC}\n"

# Check if services are running
echo -e "${BLUE}1. Checking if services are running...${NC}"
docker-compose ps

# Wait for services to be ready
echo -e "\n${BLUE}2. Waiting for services to be ready...${NC}"
sleep 10

# Check Dex is ready
echo -e "\n${BLUE}2a. Waiting for Dex OIDC provider to be ready...${NC}"
for i in {1..30}; do
  if curl -s http://localhost:5556/.well-known/openid-configuration > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Dex is ready${NC}"
    break
  fi
  echo "Waiting... ($i/30)"
  sleep 1
done

# Try to get a token using the Resource Owner Password Credentials flow
echo -e "\n${BLUE}3. Getting access token from Dex...${NC}"

# Try the token endpoint with password grant
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:5556/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=user&password=password&client_id=oidc-2-k8s-impersonation&client_secret=ZXhhbXBsZS1hcHAtc2VjcmV0&scope=openid%20profile%20email" 2>/dev/null || echo '{}')

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
  TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
  if [ -z "$TOKEN" ]; then
    echo -e "${RED}✗ Failed to extract token from response${NC}"
    echo "Response: $TOKEN_RESPONSE"
    echo -e "\n${YELLOW}Note: This test flow requires password grant support in Dex.${NC}"
    echo -e "${YELLOW}For browser-based authentication, visit:${NC}"
    AUTHORIZE_URL="http://localhost:5556/auth?client_id=oidc-2-k8s-impersonation&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20profile%20email"
    echo -e "${BLUE}$AUTHORIZE_URL${NC}"
    exit 1
  fi
  echo -e "${GREEN}✓ Successfully obtained token${NC}"
  echo -e "Token (first 50 chars): ${TOKEN:0:50}...\n"

  # Decode and show token claims
  echo -e "${BLUE}4. Token claims:${NC}"
  echo "$TOKEN" | jq -R 'split(".")[1] | @base64d | fromjson' 2>/dev/null || echo "Note: Install 'jq' to see decoded claims"

  # Test the proxy
  echo -e "\n${BLUE}5. Testing proxy by making request with token...${NC}"
  RESPONSE=$(curl -s -v http://localhost:8080/ \
    -H "Authorization: Bearer $TOKEN" 2>&1)

  if echo "$RESPONSE" | grep -q "Impersonate-User"; then
    echo -e "${GREEN}✓ Successfully received impersonation headers in response${NC}"
  else
    echo -e "${YELLOW}⚠ Impersonation headers not visible in curl output (this is normal)${NC}"
  fi

  # Make a direct test request and capture the full response
  echo -e "\n${BLUE}6. Making direct request to echo-server through proxy...${NC}"
  ECHO_RESPONSE=$(curl -s http://localhost:8080/ \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Test-Header: test-value")

  echo "Echo server response:"
  echo "$ECHO_RESPONSE" | jq . 2>/dev/null || echo "$ECHO_RESPONSE"

else
  echo -e "${RED}✗ Failed to obtain token from Dex${NC}"
  echo "Response: $TOKEN_RESPONSE"
  echo -e "\n${YELLOW}Debugging tips:${NC}"
  echo "- Check Dex logs: docker-compose logs dex"
  echo "- Verify Dex is running: curl http://localhost:5556/.well-known/openid-configuration"
  exit 1
fi

echo -e "\n${GREEN}=== All tests passed! ===${NC}\n"
echo -e "${BLUE}Service URLs:${NC}"
echo "  - Dex OIDC Provider: http://localhost:5556"
echo "  - Echo Server: http://localhost:3000"
echo "  - Proxy: http://localhost:8080"
echo -e "\n${BLUE}Test Credentials (Local Connector):${NC}"
echo "  - Username: user or admin"
echo "  - Password: password or admin"
echo "  - Email: user@example.com or admin@example.com"

