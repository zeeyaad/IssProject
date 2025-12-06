interface RequestOptions {
  method?: string;
  token?: string | null;
  body?: string;
}

export async function makeRequest<T = unknown>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const baseURL = import.meta.env.VITE_API_URL || '';
  const url = `${baseURL}${endpoint}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  // Fallback: include Authorization header if a token is available
  const storedToken = typeof window !== 'undefined' ? localStorage.getItem('authToken') : null;
  const bearer = options.token ?? storedToken;
  if (bearer) {
    headers['Authorization'] = `Bearer ${bearer}`;
  }

  const response = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body,
    credentials: 'include'  // ✅ Send httpOnly cookies with requests
  });

  const contentType = response.headers.get('content-type') || '';

  if (!response.ok) {
    // Try to parse JSON error; otherwise fallback to text
    if (contentType.includes('application/json')) {
      try {
        const error = await response.json();
        throw new Error(error.message || error.error || 'Request failed');
      } catch (e) {
        if (e instanceof Error) throw e;
        throw new Error(`Request failed with status ${response.status}`);
      }
    }
    try {
      const text = await response.text();
      const message = text?.trim() || `Request failed with status ${response.status}`;
      throw new Error(message);
    } catch (e) {
      if (e instanceof Error) throw e;
      throw new Error(`Request failed with status ${response.status}`);
    }
  }

  // Handle empty/no-content responses gracefully
  if (response.status === 204 || contentType === '') {
    return null as unknown as T;
  }

  if (contentType.includes('application/json')) {
    return response.json() as Promise<T>;
  }

  // Fallback: return text for non-JSON responses
  return response.text() as unknown as Promise<T>;
}

export function sanitizeInput(input: string): string {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}
