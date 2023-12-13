import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

require('@craftzdog/react-native-buffer');

global.Buffer = require('@craftzdog/react-native-buffer').Buffer;
global.process = require('process');

AppRegistry.registerComponent(appName, () => App);
