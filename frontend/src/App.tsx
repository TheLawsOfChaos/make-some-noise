import { Routes, Route, NavLink } from 'react-router-dom';
import {
  HomeIcon,
  BoltIcon,
  ServerStackIcon,
  DocumentTextIcon,
  SignalIcon,
  SunIcon,
  MoonIcon,
} from '@heroicons/react/24/outline';
import Dashboard from './pages/Dashboard';
import Generate from './pages/Generate';
import NoiseGenerator from './pages/NoiseGenerator';
import Destinations from './pages/Destinations';
import Templates from './pages/Templates';
import { useTheme } from './context/ThemeContext';

const navigation = [
  { name: 'Dashboard', href: '/', icon: HomeIcon },
  { name: 'Generate Events', href: '/generate', icon: BoltIcon },
  { name: 'Noise Generator', href: '/noise', icon: SignalIcon },
  { name: 'Destinations', href: '/destinations', icon: ServerStackIcon },
  { name: 'Templates', href: '/templates', icon: DocumentTextIcon },
];

function App() {
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="min-h-screen flex bg-gray-50 dark:bg-slate-900 transition-colors">
      {/* Sidebar */}
      <div className="relative w-64 bg-slate-900 dark:bg-slate-950 text-white flex flex-col">
        <div className="p-6">
          <h1 className="text-xl font-bold flex items-center gap-2">
            Make Some Noise
          </h1>
          <img
            src={theme === 'dark' ? '/makesomenoise-dark.png' : '/makesomenoise-light.png'}
            alt="Make Some Noise Logo"
            className="mt-4 w-32 h-32 object-contain"
          />
        </div>
        <nav className="mt-2">
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                `flex items-center gap-3 px-6 py-3 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-gray-800 text-white border-l-4 border-primary-500'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white border-l-4 border-transparent'
                }`
              }
            >
              <item.icon className="h-5 w-5" />
              {item.name}
            </NavLink>
          ))}
        </nav>

        {/* Dark Mode Toggle */}
        <div className="absolute bottom-0 w-64 p-4 border-t border-slate-700">
          <button
            onClick={toggleTheme}
            className="flex items-center gap-3 w-full px-4 py-2 text-sm font-medium text-gray-300 hover:bg-slate-800 hover:text-white rounded-md transition-colors"
          >
            {theme === 'light' ? (
              <>
                <MoonIcon className="h-5 w-5" />
                Dark Mode
              </>
            ) : (
              <>
                <SunIcon className="h-5 w-5" />
                Light Mode
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <main className="p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/generate" element={<Generate />} />
            <Route path="/noise" element={<NoiseGenerator />} />
            <Route path="/destinations" element={<Destinations />} />
            <Route path="/templates" element={<Templates />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;
