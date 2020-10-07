package main

//todo: generic
type Key = string
type Value = *UserConfig
type T = map[Key]Value

func Filter(m T, f func(Key, Value) bool) T {
	result := T{}
	for key, value := range m {
		if f(key, value) {
			result[key] = value
		}
	}
	return result
}
