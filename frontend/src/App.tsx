import { Routes, Route, NavLink } from 'react-router-dom';
import {
  HomeIcon,
  BoltIcon,
  ServerStackIcon,
  DocumentTextIcon,
  SignalIcon,
} from '@heroicons/react/24/outline';
import Dashboard from './pages/Dashboard';
import Generate from './pages/Generate';
import NoiseGenerator from './pages/NoiseGenerator';
import Destinations from './pages/Destinations';
import Templates from './pages/Templates';

const navigation = [
  { name: 'Dashboard', href: '/', icon: HomeIcon },
  { name: 'Generate Events', href: '/generate', icon: BoltIcon },
  { name: 'Noise Generator', href: '/noise', icon: SignalIcon },
  { name: 'Destinations', href: '/destinations', icon: ServerStackIcon },
  { name: 'Templates', href: '/templates', icon: DocumentTextIcon },
];

function App() {
  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white">
        <div className="p-6">
          <h1 className="text-xl font-bold flex items-center gap-2">
            <BoltIcon className="h-6 w-6 text-primary-400" />
            SIEM Event Gen
          </h1>
        </div>
        <nav className="mt-6">
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
