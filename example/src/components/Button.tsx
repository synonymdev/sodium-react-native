import React, { type ReactElement } from 'react';
import {
  View,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  type TouchableOpacityProps,
} from 'react-native';
import Text from './Text';

type ButtonProps = TouchableOpacityProps & {
  title: string;
  loading?: boolean;
};

const Button = ({
  title,
  loading = false,
  style,
  ...props
}: ButtonProps): ReactElement => (
  <TouchableOpacity
    style={[styles.root, style]}
    activeOpacity={0.6}
    disabled={loading}
    {...props}
  >
    <Text style={styles.text} numberOfLines={1}>
      {title}
    </Text>

    {loading && (
      <View style={styles.loading}>
        <ActivityIndicator size="small" />
      </View>
    )}
  </TouchableOpacity>
);

const styles = StyleSheet.create({
  root: {
    backgroundColor: '#dedede',
    alignItems: 'center',
    justifyContent: 'center',
    flexDirection: 'row',
    borderRadius: 5,
    paddingVertical: 4,
    paddingHorizontal: 16,
    minWidth: 300,
  },
  loading: {
    ...StyleSheet.absoluteFillObject,
    alignItems: 'center',
    justifyContent: 'center',
    alignSelf: 'center',
    borderRadius: 54,
    paddingVertical: 12,
    paddingHorizontal: 16,
  },
  text: {
    color: 'black',
    fontSize: 14,
  },
});

export default Button;
