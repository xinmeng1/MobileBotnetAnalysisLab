
__author__ = 'mengxin'
#

multilist = [[[0 for col in range(0)] for row in range(0)] for high in range(100)]
# a[0][0] = 1
# print a
# append a row
array1 = ['111','111','111','111']
array2 = ['222','222','222','222']
array3 = ['333','333','333','333']
array4 = ['444','444','444','444']
array5 = ['555','555','555','555']
array6 = ['666','666','666','666']

# a[0].append(array1)
# a[0].append(array2)
# a[5].append(array5)
# a[3].append(array3)
# a[3].append(array4)

multilist[0].append(array2)
multilist[5].append(array5)
multilist[3].append(array3)
multilist[3].append(array4)

# a.append([])
# a[0].append(array1)
# a[0].append(array2)
# a.insert(3,[array1])
# # a.append(5)
# # # a[3].append(array3)
# a.insert(2,[array4])
# a.insert(1,[array5,array6])
# a[1].append(array1)
# a[0] = [array1]
# a[0] = [array2] + a[0]
# a[1] = [array3]
# a[1] = [array4] + a[1]
# a[1] = [array5] + a[1]
# a[2] = [array6]

print multilist
for x in multilist:
    print x
    print len(x)

# # delete a row
# del a[0]
# print a
# # append a col
# for i in range(len(a)):
#     a[i] = [0] + a[i]
# a[i].insert(1, 2)
# print a
# # delete a col
# for i in range(len(a)):
#     del a[i][0]
# print a