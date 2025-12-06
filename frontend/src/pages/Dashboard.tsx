import { useState, useEffect } from 'react';
import type { FC, ChangeEvent, FormEvent } from 'react';
import { useAuth } from '../hooks/useAuth';
import { makeRequest, sanitizeInput } from '../utils/api';

interface Message {
  text: string;
  type: string;
}

interface SearchResult {
  id: number;
  username: string;
}

interface VaultItem {
  id: number;
  title: string;
  created_at: string;
  updated_at: string;
}

interface RevealedSecret {
  itemId: number;
  value: string;
  revealedAt: number;
}

const Dashboard: FC = () => {
  const { user, token } = useAuth();

  // Vault items state
  const [vaultItems, setVaultItems] = useState<VaultItem[]>([]);
  const [revealedSecrets, setRevealedSecrets] = useState<RevealedSecret[]>([]);
  const [newSecretTitle, setNewSecretTitle] = useState('');
  const [newSecretValue, setNewSecretValue] = useState('');

  // Legacy state (search functionality)
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<Message>({ text: '', type: '' });

  const showMessage = (text: string, type: string = 'error'): void => {
    setMessage({ text, type });
    setTimeout(() => setMessage({ text: '', type: '' }), 5000);
  };

  // Fetch vault items when component mounts
  useEffect(() => {
    fetchVaultItems();
  }, []);

  const fetchVaultItems = async (): Promise<void> => {
    try {
      const data = await makeRequest<{ items: VaultItem[] }>('/api/vault/items'); // Token in cookie
      setVaultItems(data.items);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to fetch vault items';
      showMessage(message);
    }
  };

  const handleCreateSecret = async (e: FormEvent): Promise<void> => {
    e.preventDefault();

    if (!newSecretTitle.trim() || !newSecretValue.trim()) {
      showMessage('Both title and secret value are required');
      return;
    }

    setLoading(true);
    try {
      await makeRequest('/api/vault/items', {
        method: 'POST',
        body: JSON.stringify({ title: newSecretTitle, secret_value: newSecretValue })
      });
      showMessage('Secret added successfully!', 'success');
      setNewSecretTitle('');
      setNewSecretValue('');
      await fetchVaultItems(); // Refresh list
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to create secret';
      showMessage(message);
    } finally {
      setLoading(false);
    }
  };

  const handleRevealSecret = async (itemId: number): Promise<void> => {
    setLoading(true);
    try {
      const data = await makeRequest<{ secret_value: string }>(
        `/api/vault/items/${itemId}/decrypt`,
        { method: 'POST' } // Token in cookie
      );

      setRevealedSecrets(prev => [...prev, {
        itemId,
        value: data.secret_value,
        revealedAt: Date.now()
      }]);

      showMessage('Secret revealed successfully!', 'success');

      // Auto-hide after 30 seconds
      setTimeout(() => {
        setRevealedSecrets(prev => prev.filter(s => s.itemId !== itemId));
      }, 30000);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to decrypt secret';
      showMessage(message);
    } finally {
      setLoading(false);
    }
  };

  const handleHideSecret = (itemId: number): void => {
    setRevealedSecrets(prev => prev.filter(s => s.itemId !== itemId));
  };

  const handleDeleteSecret = async (itemId: number, title: string): Promise<void> => {
    if (!window.confirm(`Are you sure you want to delete "${title}"?`)) {
      return;
    }

    setLoading(true);
    try {
      await makeRequest(`/api/vault/items/${itemId}`, {
        method: 'DELETE'
      });
      showMessage('Secret deleted successfully!', 'success');
      await fetchVaultItems(); // Refresh list
      // Also remove from revealed secrets if it was revealed
      setRevealedSecrets(prev => prev.filter(s => s.itemId !== itemId));
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to delete secret';
      showMessage(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async (): Promise<void> => {
    if (!searchQuery.trim()) {
      showMessage('Please enter a search query');
      return;
    }

    setLoading(true);
    try {
      const data = await makeRequest<{ results: SearchResult[] }>(`/search?query=${encodeURIComponent(searchQuery)}`);
      setSearchResults(data.results);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Search failed';
      showMessage(message);
    } finally {
      setLoading(false);
    }
  };

  const securityItems = [
    { name: 'Encryption', status: 'AES-256-GCM Active', icon: '🔒', color: 'text-[#00C9A7]', bg: 'bg-[#00C9A7]/10' },
    { name: 'Authentication', status: 'JWT Valid', icon: '✅', color: 'text-[#6D5DF5]', bg: 'bg-[#6D5DF5]/10' },
    { name: 'Session', status: 'Secure', icon: '🛡️', color: 'text-[#9B7CFF]', bg: 'bg-[#9B7CFF]/10' },
    { name: 'Input Validation', status: 'Active', icon: '🔍', color: 'text-[#FF6B6B]', bg: 'bg-[#FF6B6B]/10' }
  ];

  return (
    <div className="min-h-screen w-full box-border bg-[#F3F6FB] text-[#2D3748] font-sans">
      <main className="w-full box-border px-0 py-10 space-y-10">

        {/* Message Toast */}
        {message.text && (
          <div className={`fixed top-28 right-8 z-50 transform transition-all duration-300 animate-fade-in-down ${message.type === 'success'
            ? 'bg-[#00C9A7] text-white shadow-[#00C9A7]/30'
            : 'bg-[#FF6B6B] text-white shadow-[#FF6B6B]/30'
            } px-6 py-4 rounded-2xl shadow-xl max-w-md flex items-center gap-4 backdrop-blur-sm`}>
            <span className="text-2xl bg-white/20 p-1.5 rounded-full">
              {message.type === 'success' ? '✅' : '⚠️'}
            </span>
            <p className="font-semibold text-sm">{message.text}</p>
          </div>
        )}

        {/* Welcome Section */}
        <div className="relative w-full bg-gradient-to-r from-[#6D5DF5] to-[#9B7CFF] rounded-3xl p-10 text-white shadow-2xl shadow-[#6D5DF5]/20 overflow-hidden">
          <div className="absolute top-0 right-0 w-80 h-80 bg-white opacity-10 rounded-full -mr-20 -mt-20 blur-3xl mix-blend-overlay"></div>
          <div className="absolute bottom-0 left-0 w-60 h-60 bg-[#00C9A7] opacity-20 rounded-full -ml-20 -mb-20 blur-3xl mix-blend-overlay"></div>

          <div className="relative z-10 space-y-3">
            <h2 className="text-4xl font-bold tracking-tight">Welcome back, {user?.username}!</h2>
            {/* <p className="text-indigo-50 text-lg font-medium max-w-2xl leading-relaxed opacity-90">
              Email: <span className="font-semibold">{user?.email}</span><br />
              Your secure vault is active. All secrets are protected with military-grade AES-256-GCM encryption.
            </p> */}
          </div>
        </div>

        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 w-full">

          {/* Add New Secret Card */}
          <div className="bg-white rounded-3xl shadow-sm border border-[#E8ECF2] overflow-hidden hover:shadow-xl hover:border-[#6D5DF5]/20 transition-all duration-300">
            <div className="p-8 border-b border-[#E8ECF2] bg-gradient-to-b from-white to-[#F3F6FB]/50">
              <div className="flex items-center gap-4 mb-3">
                <div className="p-3 bg-[#6D5DF5]/10 rounded-2xl text-[#6D5DF5]">
                  <span className="text-2xl">➕</span>
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-gray-900">Add New Secret</h3>
                  <p className="text-[#7A8699] text-sm font-medium mt-1">
                    Encrypt and store sensitive data
                  </p>
                </div>
              </div>
            </div>

            <form onSubmit={handleCreateSecret} className="p-8 space-y-6">
              <div>
                <label htmlFor="secret-title" className="block text-sm font-bold text-gray-700 mb-3 ml-1">
                  Secret Title
                </label>
                <input
                  type="text"
                  id="secret-title"
                  value={newSecretTitle}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => setNewSecretTitle(e.target.value)}
                  className="w-full px-5 py-4 bg-[#F3F6FB] border border-[#E8ECF2] rounded-2xl text-gray-800 placeholder-[#7A8699] focus:outline-none focus:ring-2 focus:ring-[#6D5DF5] focus:border-transparent transition-all duration-200 text-base"
                  placeholder="e.g., Gmail Password, API Key, etc."
                />
              </div>

              <div>
                <label htmlFor="secret-value" className="block text-sm font-bold text-gray-700 mb-3 ml-1">
                  Secret Value
                </label>
                <textarea
                  id="secret-value"
                  value={newSecretValue}
                  onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setNewSecretValue(e.target.value)}
                  rows={4}
                  className="w-full px-5 py-4 bg-[#F3F6FB] border border-[#E8ECF2] rounded-2xl text-gray-800 placeholder-[#7A8699] focus:outline-none focus:ring-2 focus:ring-[#6D5DF5] focus:border-transparent transition-all duration-200 resize-none text-base font-mono"
                  placeholder="Enter your secret value..."
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-[#6D5DF5] to-[#9B7CFF] hover:brightness-110 text-white py-4 px-6 rounded-2xl font-bold text-sm uppercase tracking-wide shadow-lg shadow-[#6D5DF5]/30 transition-all duration-200 transform hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? <span className="animate-spin">↻</span> : '🔒 Encrypt & Save Secret'}
              </button>
            </form>
          </div>

          {/* Vault Items List */}
          <div className="bg-white rounded-3xl shadow-sm border border-[#E8ECF2] overflow-hidden hover:shadow-xl hover:border-[#6D5DF5]/20 transition-all duration-300">
            <div className="p-8 border-b border-[#E8ECF2] bg-gradient-to-b from-white to-[#F3F6FB]/50">
              <div className="flex items-center gap-4 mb-3">
                <div className="p-3 bg-[#9B7CFF]/10 rounded-2xl text-[#9B7CFF]">
                  <span className="text-2xl">🗝️</span>
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-gray-900">Your Secrets</h3>
                  <p className="text-[#7A8699] text-sm font-medium mt-1">
                    {vaultItems.length} {vaultItems.length === 1 ? 'secret' : 'secrets'} stored
                  </p>
                </div>
              </div>
            </div>

            <div className="p-8 max-h-[600px] overflow-y-auto">
              {vaultItems.length === 0 ? (
                <div className="flex flex-col items-center justify-center text-[#7A8699] py-12 space-y-3">
                  <span className="text-5xl opacity-20">📭</span>
                  <p className="text-sm font-medium">No secrets yet. Add your first secret!</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {vaultItems.map(item => {
                    const revealed = revealedSecrets.find(s => s.itemId === item.id);

                    return (
                      <div
                        key={item.id}
                        className="p-5 bg-[#F3F6FB] rounded-2xl border border-[#E8ECF2] hover:border-[#6D5DF5]/30 transition-all duration-200"
                      >
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex-1">
                            <h4 className="text-lg font-bold text-gray-900">{item.title}</h4>
                            <p className="text-xs text-[#7A8699] mt-1">
                              Created: {new Date(item.created_at).toLocaleDateString()}
                            </p>
                          </div>
                          <button
                            onClick={() => handleDeleteSecret(item.id, item.title)}
                            className="p-2 hover:bg-red-50 rounded-xl transition-colors"
                            title="Delete secret"
                          >
                            🗑️
                          </button>
                        </div>

                        {!revealed ? (
                          <button
                            onClick={() => handleRevealSecret(item.id)}
                            disabled={loading}
                            className="w-full bg-white border-2 border-[#6D5DF5] text-[#6D5DF5] hover:bg-[#6D5DF5]/5 py-3 px-4 rounded-xl font-bold text-sm uppercase tracking-wide transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50"
                          >
                            {loading ? <span className="animate-spin">↻</span> : <>👁️ Reveal Secret</>}
                          </button>
                        ) : (
                          <div className="space-y-3">
                            <div className="p-4 bg-white rounded-xl border border-[#00C9A7]/20">
                              <p className="text-xs font-bold text-[#00C9A7] uppercase tracking-wider mb-2">Decrypted Value</p>
                              <p className="text-gray-800 font-mono text-sm break-all">{revealed.value}</p>
                            </div>
                            <button
                              onClick={() => handleHideSecret(item.id)}
                              className="w-full bg-[#7A8699] hover:bg-[#5A6679] text-white py-2 px-4 rounded-xl font-bold text-sm transition-all duration-200"
                            >
                              🙈 Hide Secret
                            </button>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Security Status Footer */}
        <div className="bg-white rounded-3xl shadow-sm border border-[#E8ECF2] p-8 hover:shadow-lg transition-all duration-300">
          <h3 className="text-xl font-bold text-gray-900 mb-8 flex items-center gap-3">
            <span className="w-1.5 h-8 bg-[#00C9A7] rounded-full"></span>
            System Security Status
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {securityItems.map((item) => (
              <div key={item.name} className={`flex items-center gap-5 p-5 rounded-2xl ${item.bg} border border-transparent hover:scale-[1.02] transition-all duration-300 cursor-default`}>
                <span className="text-3xl filter drop-shadow-sm">{item.icon}</span>
                <div>
                  <div className="font-bold text-gray-900 text-base">{item.name}</div>
                  <div className={`text-sm font-bold ${item.color} mt-0.5`}>{item.status}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
